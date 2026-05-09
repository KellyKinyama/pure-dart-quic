// HTTP/3 reverse proxy with HTTP/1.1 *and* HTTP/2 origin support.
//
// Wraps [Http3Server] so every inbound HTTP/3 request is forwarded to
// a backend HTTP origin, then streams the upstream response (status,
// headers, and body chunks) back over HTTP/3 without buffering the
// full body in memory.
//
// Origin protocol selection:
//
//   * `http://` → HTTP/1.1 over plain TCP via `dart:io`'s `HttpClient`.
//     If [allowH2c] is true, the proxy instead opens a raw TCP socket
//     and speaks HTTP/2 with prior knowledge (RFC 7540 §3.4 — h2c).
//   * `https://` → TLS with ALPN advertising both `h2` and `http/1.1`.
//     Whichever the origin selects is used. (For `h2` the proxy uses
//     `package:http2`; otherwise it falls back to `HttpClient`.)
//
// Hop-by-hop headers (RFC 7230 §6.1) are stripped in both directions
// per HTTP/3 (RFC 9114 §4.2). The proxy adds `Via:` and the
// conventional `X-Forwarded-{For,Host,Proto}` headers on the upstream
// request, and keeps the response body chunked (no Content-Length
// rewriting) end-to-end on the HTTP/3 leg.
//
// Connection re-use:
//
//   * HTTP/1.1: handled by `HttpClient`'s built-in keep-alive pool.
//   * HTTP/2: one [ClientTransportConnection] per origin (scheme +
//     host + port) is cached on the proxy; concurrent requests
//     multiplex onto its streams.
//
// Usage:
//
// ```dart
// final proxy = Http3ReverseProxy(target: Uri.parse('https://example.com'));
// await proxy.bind('127.0.0.1', 4433);
// ```

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http2/transport.dart' as h2;

import 'h3_protocol.dart';
import 'http3_server.dart';

/// Resolves the upstream origin URI for a given inbound HTTP/3 request.
typedef Http3ReverseProxyResolver = FutureOr<Uri> Function(Http3Request req);

/// Hop-by-hop headers that MUST NOT be forwarded across a proxy
/// (RFC 7230 §6.1) plus HTTP/2/3 pseudo-headers.
const Set<String> _hopByHop = <String>{
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  ':status',
  ':method',
  ':path',
  ':scheme',
  ':authority',
  ':protocol',
};

/// HTTP/3 reverse proxy — accepts HTTP/3 requests on a UDP socket and
/// forwards each one to a backend HTTP/1.1 or HTTP/2 origin.
class Http3ReverseProxy {
  final Http3Server _server = Http3Server();
  final HttpClient _client;
  final Http3ReverseProxyResolver _resolve;
  final Map<String, _H2Origin> _h2Origins = <String, _H2Origin>{};

  /// If true (default), preserves the inbound `:path` + query string
  /// when constructing the upstream URL. When false, the resolver's
  /// returned [Uri] is used verbatim.
  final bool preserveRequestPath;

  /// If true, accept upstream TLS certificates that fail validation.
  /// Useful for self-signed origins in dev/test. Default false.
  final bool allowInsecureUpstreamCertificates;

  /// If true, talk HTTP/2 over plaintext TCP ("h2c" with prior
  /// knowledge) when the upstream scheme is `http`. Default false —
  /// almost no real-world origin supports this.
  final bool allowH2c;

  /// Optional `Via:` header pseudonym to advertise. RFC 7230 §5.7.1.
  /// Default: `pure-dart-quic`.
  final String viaPseudonym;

  /// Construct a proxy that always forwards to [target].
  Http3ReverseProxy({
    required Uri target,
    HttpClient? client,
    this.preserveRequestPath = true,
    this.allowInsecureUpstreamCertificates = false,
    this.allowH2c = false,
    this.viaPseudonym = 'pure-dart-quic',
  }) : _client = client ?? _newHttpClient(allowInsecureUpstreamCertificates),
       _resolve = ((_) => target);

  /// Per-request resolver variant.
  Http3ReverseProxy.resolver({
    required Http3ReverseProxyResolver resolver,
    HttpClient? client,
    this.preserveRequestPath = true,
    this.allowInsecureUpstreamCertificates = false,
    this.allowH2c = false,
    this.viaPseudonym = 'pure-dart-quic',
  }) : _client = client ?? _newHttpClient(allowInsecureUpstreamCertificates),
       _resolve = resolver;

  static HttpClient _newHttpClient(bool insecure) {
    final c = HttpClient();
    if (insecure) {
      c.badCertificateCallback = (_, _, _) => true;
    }
    return c;
  }

  InternetAddress? get address => _server.address;
  int? get port => _server.port;

  /// Bind the QUIC/UDP socket and start proxying.
  Future<void> bind(dynamic address, int port) async {
    _server.any('/*', _proxy);
    _server.fallback = _proxy; // catch '/'
    await _server.bind(address, port);
  }

  Future<void> close() async {
    _client.close(force: true);
    for (final o in _h2Origins.values.toList()) {
      await o.close();
    }
    _h2Origins.clear();
    await _server.close();
  }

  // -------------------------------------------------------------------------
  Future<void> _proxy(Http3Request req) async {
    Uri target;
    try {
      target = await _resolve(req);
    } catch (e) {
      _fail(req, 502, 'resolver error: $e');
      return;
    }

    final upstream = preserveRequestPath
        ? target.replace(
            path: _joinPath(target.path, req.path),
            query: _queryFrom(req.path, target.query),
          )
        : target;

    try {
      if (upstream.scheme == 'https') {
        await _forwardSecure(req, upstream);
      } else if (upstream.scheme == 'http') {
        if (allowH2c) {
          await _forwardH2c(req, upstream);
        } else {
          await _forwardH1(req, upstream);
        }
      } else {
        _fail(req, 502, 'unsupported upstream scheme: ${upstream.scheme}');
      }
    } catch (e) {
      _fail(req, 502, 'upstream error: $e');
    }
  }

  // -------------------------------------------------------------------------
  // HTTPS: ALPN-negotiated h2 / http/1.1
  // -------------------------------------------------------------------------
  Future<void> _forwardSecure(Http3Request req, Uri upstream) async {
    final originKey = _originKey(upstream);

    // Reuse a live h2 origin connection if we have one.
    final pooled = _h2Origins[originKey];
    if (pooled != null && pooled.isOpen) {
      await _forwardH2(req, upstream, pooled);
      return;
    }

    final port = upstream.hasPort ? upstream.port : 443;
    final secure = await SecureSocket.connect(
      upstream.host,
      port,
      supportedProtocols: const ['h2', 'http/1.1'],
      onBadCertificate: allowInsecureUpstreamCertificates ? (_) => true : null,
    );

    if (secure.selectedProtocol == 'h2') {
      final h2c = h2.ClientTransportConnection.viaSocket(secure);
      final origin = _H2Origin(originKey, h2c, secure, _h2Origins);
      _h2Origins[originKey] = origin;
      await _forwardH2(req, upstream, origin);
    } else {
      // ALPN selected http/1.1 (or none) — close the raw socket and
      // fall through to the HttpClient pool.
      await secure.close();
      await _forwardH1(req, upstream);
    }
  }

  // -------------------------------------------------------------------------
  // h2c (plaintext HTTP/2 with prior knowledge)
  // -------------------------------------------------------------------------
  Future<void> _forwardH2c(Http3Request req, Uri upstream) async {
    final originKey = _originKey(upstream);
    final pooled = _h2Origins[originKey];
    if (pooled != null && pooled.isOpen) {
      await _forwardH2(req, upstream, pooled);
      return;
    }

    final port = upstream.hasPort ? upstream.port : 80;
    final socket = await Socket.connect(upstream.host, port);
    final h2c = h2.ClientTransportConnection.viaSocket(socket);
    final origin = _H2Origin(originKey, h2c, socket, _h2Origins);
    _h2Origins[originKey] = origin;
    await _forwardH2(req, upstream, origin);
  }

  // -------------------------------------------------------------------------
  // HTTP/2 forwarding (shared by https-h2 and h2c)
  // -------------------------------------------------------------------------
  Future<void> _forwardH2(
    Http3Request req,
    Uri upstream,
    _H2Origin origin,
  ) async {
    final h2Headers = <h2.Header>[
      h2.Header.ascii(':method', req.method),
      h2.Header.ascii(':scheme', upstream.scheme),
      h2.Header.ascii(
        ':authority',
        upstream.hasPort ? '${upstream.host}:${upstream.port}' : upstream.host,
      ),
      h2.Header.ascii(':path', _pathAndQuery(upstream)),
      for (final entry in req.headers.entries)
        if (!entry.key.startsWith(':') &&
            !_hopByHop.contains(entry.key.toLowerCase()))
          h2.Header.ascii(entry.key.toLowerCase(), entry.value),
      ..._forwardedHeadersAsH2(req, upstream),
    ];

    final body = await req.body;
    final endStream = body.isEmpty;
    final h2Stream = origin.connection.makeRequest(
      h2Headers,
      endStream: endStream,
    );
    if (!endStream) {
      h2Stream.outgoingMessages.add(
        h2.DataStreamMessage(body, endStream: true),
      );
    }
    await h2Stream.outgoingMessages.close();

    var sentH3Headers = false;
    var firstChunk = true;
    await for (final msg in h2Stream.incomingMessages) {
      if (msg is h2.HeadersStreamMessage && !sentH3Headers) {
        final outHeaders = <String, String>{};
        var status = 502;
        for (final h in msg.headers) {
          final name = ascii.decode(h.name);
          final value = ascii.decode(h.value);
          if (name == ':status') {
            status = int.tryParse(value) ?? 502;
            continue;
          }
          if (_hopByHop.contains(name.toLowerCase())) continue;
          outHeaders[name.toLowerCase()] = value;
        }
        outHeaders['via'] = '2 $viaPseudonym';
        req.respondHeaders(status, headers: outHeaders);
        sentH3Headers = true;
      } else if (msg is h2.DataStreamMessage) {
        if (!sentH3Headers) {
          // Trailers/Continuations or 1xx informational — for HTTP/3
          // we only forward final headers; just buffer until they
          // arrive (rare).
          continue;
        }
        final chunk = msg.bytes is Uint8List
            ? msg.bytes as Uint8List
            : Uint8List.fromList(msg.bytes);
        if (firstChunk && chunk.isEmpty && !msg.endStream) {
          continue;
        }
        firstChunk = false;
        req.writeBody(chunk);
      }
    }
    if (!sentH3Headers) {
      _fail(req, 502, 'upstream closed without HEADERS');
      return;
    }
    req.endResponse();
  }

  // -------------------------------------------------------------------------
  // HTTP/1.1 forwarding via dart:io HttpClient
  // -------------------------------------------------------------------------
  Future<void> _forwardH1(Http3Request req, Uri upstream) async {
    HttpClientRequest upReq;
    try {
      upReq = await _client.openUrl(req.method, upstream);
    } on SocketException catch (e) {
      _fail(req, 502, 'upstream connect failed: ${e.message}');
      return;
    }

    req.headers.forEach((name, value) {
      if (name.startsWith(':')) return;
      if (_hopByHop.contains(name.toLowerCase())) return;
      upReq.headers.set(name, value);
    });
    upReq.headers.host = upstream.host;
    if (upstream.hasPort) upReq.headers.port = upstream.port;
    _addForwardedHeaders(req, upstream, (n, v) => upReq.headers.set(n, v));

    final body = await req.body;
    if (body.isNotEmpty) {
      upReq.contentLength = body.length;
      upReq.add(body);
    }

    HttpClientResponse upRes;
    try {
      upRes = await upReq.close();
    } on SocketException catch (e) {
      _fail(req, 502, 'upstream IO error: ${e.message}');
      return;
    }

    final outHeaders = <String, String>{};
    upRes.headers.forEach((name, values) {
      final lower = name.toLowerCase();
      if (_hopByHop.contains(lower)) return;
      outHeaders[lower] = values.join(', ');
    });
    outHeaders['via'] = '1.1 $viaPseudonym';

    req.respondHeaders(upRes.statusCode, headers: outHeaders);
    try {
      await for (final chunk in upRes) {
        final bytes = chunk is Uint8List ? chunk : Uint8List.fromList(chunk);
        if (bytes.isNotEmpty) req.writeBody(bytes);
      }
    } catch (e) {
      // Best effort — close the response stream.
    }
    req.endResponse();
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------
  Iterable<h2.Header> _forwardedHeadersAsH2(Http3Request req, Uri upstream) {
    final out = <h2.Header>[];
    _addForwardedHeaders(
      req,
      upstream,
      (n, v) => out.add(h2.Header.ascii(n, v)),
    );
    return out;
  }

  void _addForwardedHeaders(
    Http3Request req,
    Uri upstream,
    void Function(String name, String value) sink,
  ) {
    final existingFor = req.headers['x-forwarded-for'];
    sink(
      'x-forwarded-for',
      existingFor == null ? 'unknown' : '$existingFor, unknown',
    );
    sink('x-forwarded-proto', req.scheme);
    sink('x-forwarded-host', req.authority);
    sink('via', '3 $viaPseudonym');
  }

  void _fail(Http3Request req, int status, String reason) {
    try {
      req.respond(
        status,
        headers: const {'content-type': 'text/plain; charset=utf-8'},
        body: Uint8List.fromList(reason.codeUnits),
      );
    } on StateError {
      // Already responded — drop chunks on the floor.
    }
  }

  static String _originKey(Uri u) =>
      '${u.scheme}://${u.host}:${u.hasPort ? u.port : (u.scheme == 'https' ? 443 : 80)}';

  static String _pathAndQuery(Uri u) {
    final p = u.path.isEmpty ? '/' : u.path;
    return u.query.isEmpty ? p : '$p?${u.query}';
  }

  // The inbound :path may contain a query string ("?...") — split it
  // and merge with the target's existing query.
  static String _joinPath(String basePath, String reqPath) {
    final qIdx = reqPath.indexOf('?');
    final pathOnly = qIdx >= 0 ? reqPath.substring(0, qIdx) : reqPath;
    if (basePath.isEmpty || basePath == '/') return pathOnly;
    final b = basePath.endsWith('/')
        ? basePath.substring(0, basePath.length - 1)
        : basePath;
    final p = pathOnly.startsWith('/') ? pathOnly : '/$pathOnly';
    return '$b$p';
  }

  static String _queryFrom(String reqPath, String baseQuery) {
    final qIdx = reqPath.indexOf('?');
    final reqQuery = qIdx >= 0 ? reqPath.substring(qIdx + 1) : '';
    if (baseQuery.isEmpty) return reqQuery;
    if (reqQuery.isEmpty) return baseQuery;
    return '$baseQuery&$reqQuery';
  }
}

/// Pooled HTTP/2 client connection to a single origin.
class _H2Origin {
  final String key;
  final h2.ClientTransportConnection connection;
  final Socket socket;
  final Map<String, _H2Origin> registry;
  bool _closed = false;

  _H2Origin(this.key, this.connection, this.socket, this.registry);

  bool get isOpen => !_closed && connection.isOpen;

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    registry.remove(key);
    try {
      await connection.terminate();
    } catch (_) {}
    try {
      await socket.close();
    } catch (_) {}
  }
}
