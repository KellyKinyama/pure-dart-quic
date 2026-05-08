// HTTP/3 → HTTP/1.1 (or HTTP/2) reverse proxy.
//
// Wraps [Http3Server] so that every inbound HTTP/3 request is
// forwarded to a backend HTTP origin reachable via dart:io's
// [HttpClient] (which speaks HTTP/1.1 with optional keep-alive). The
// origin's response — status line, headers, and body — is streamed
// back to the HTTP/3 client.
//
// Hop-by-hop headers (RFC 7230 §6.1) are stripped in both directions
// per HTTP/3 (RFC 9114 §4.2).
//
// Example:
//
// ```dart
// final proxy = Http3ReverseProxy(target: Uri.parse('http://127.0.0.1:8080'));
// await proxy.bind('127.0.0.1', 4433);
// ```
//
// You can also override the upstream URL per request by passing a
// [Http3ReverseProxyResolver] that returns the target [Uri] given the
// inbound request.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'h3_protocol.dart';
import 'http3_server.dart';

/// Resolves the upstream origin URI for a given inbound HTTP/3 request.
typedef Http3ReverseProxyResolver = FutureOr<Uri> Function(Http3Request req);

/// Hop-by-hop headers that MUST NOT be forwarded across a proxy.
const _hopByHop = <String>{
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  // HTTP/3 pseudo-headers must not appear in the body of a response.
  ':status',
  ':method',
  ':path',
  ':scheme',
  ':authority',
};

/// HTTP/3 reverse proxy — forwards every inbound request to a backend
/// HTTP/1.1 (or HTTP/2 with ALPN) origin and streams the response back.
class Http3ReverseProxy {
  final Http3Server _server = Http3Server();
  final HttpClient _client;
  final Http3ReverseProxyResolver _resolve;

  /// If true (default), preserves the inbound `:path` + query string
  /// when constructing the upstream URL. When false, the resolver's
  /// returned [Uri] is used verbatim.
  final bool preserveRequestPath;

  /// Construct a proxy that always forwards to [target]. The inbound
  /// request's path + query are appended to [target]'s authority.
  Http3ReverseProxy({
    required Uri target,
    HttpClient? client,
    this.preserveRequestPath = true,
  }) : _client = client ?? HttpClient(),
       _resolve = ((_) => target);

  /// Per-request resolver variant. The [resolver] returns the upstream
  /// origin URL for each inbound request; [preserveRequestPath] then
  /// controls whether the inbound path is appended.
  Http3ReverseProxy.resolver({
    required Http3ReverseProxyResolver resolver,
    HttpClient? client,
    this.preserveRequestPath = true,
  }) : _client = client ?? HttpClient(),
       _resolve = resolver;

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

    HttpClientRequest? upReq;
    HttpClientResponse upRes;
    try {
      upReq = await _client.openUrl(req.method, upstream);
      // Forward request headers.
      req.headers.forEach((name, value) {
        if (name.startsWith(':')) return;
        if (_hopByHop.contains(name.toLowerCase())) return;
        upReq!.headers.set(name, value);
      });
      // Authority/host on the upstream request (HttpClient sets it
      // from [upstream.authority] automatically; re-set in case the
      // origin expects a specific Host header).
      upReq.headers.host = upstream.host;
      if (upstream.hasPort) upReq.headers.port = upstream.port;

      // Forward request body if any.
      final body = await req.body;
      if (body.isNotEmpty) {
        upReq.contentLength = body.length;
        upReq.add(body);
      }
      upRes = await upReq.close();
    } on SocketException catch (e) {
      _fail(req, 502, 'upstream connect failed: ${e.message}');
      return;
    } catch (e) {
      _fail(req, 502, 'upstream error: $e');
      return;
    }

    // Drain upstream body before responding (HTTP/3 respond() in this
    // codebase writes HEADERS + DATA + FIN in one shot).
    final bodyBuilder = BytesBuilder(copy: false);
    try {
      await for (final chunk in upRes) {
        bodyBuilder.add(chunk);
      }
    } catch (e) {
      _fail(req, 502, 'upstream read error: $e');
      return;
    }

    final outHeaders = <String, String>{};
    upRes.headers.forEach((name, values) {
      final lower = name.toLowerCase();
      if (_hopByHop.contains(lower)) return;
      // RFC 9114 §4.2: header names must be lowercase in HTTP/3.
      outHeaders[lower] = values.join(', ');
    });

    final bodyBytes = bodyBuilder.toBytes();
    req.respond(
      upRes.statusCode,
      headers: outHeaders,
      body: bodyBytes.isEmpty ? null : Uint8List.fromList(bodyBytes),
    );
  }

  void _fail(Http3Request req, int status, String reason) {
    req.respond(
      status,
      headers: const {'content-type': 'text/plain; charset=utf-8'},
      body: Uint8List.fromList(reason.codeUnits),
    );
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
