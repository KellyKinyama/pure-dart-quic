// High-level HTTP/3 server API.
//
// Hides QUIC, TLS, ALPN registration and endpoint plumbing entirely.
// Application code looks like:
//
//   final app = Http3Server();
//   app.get('/',      (req) => req.respond(200, body: 'Hello'));
//   app.post('/echo', (req) async {
//     final body = await req.body;
//     req.respond(200, body: body);
//   });
//   await app.bind('127.0.0.1', 4433);
//
// Routing is exact-match per (method, path) with optional `:param`
// segments captured into [Http3Request.params]. A wildcard `*` segment
// captures the remainder of the path. Use [any] to match any method
// for a given path, [fallback] to handle anything unmatched (the
// default fallback returns 404).

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../alpn_registry.dart';
import '../../transport/quic/quic_endpoint.dart';
import 'h3_protocol.dart';

/// Application-supplied HTTP/3 request handler.
typedef Http3AppHandler = FutureOr<void> Function(Http3Request request);

class _Route {
  final String method; // upper-case, '*' = any
  final List<String> segments; // path split on '/', empty for root
  final Http3AppHandler handler;
  final bool wildcard; // last segment was '*'

  _Route(this.method, this.segments, this.handler, this.wildcard);

  /// Returns captured params if matched, null otherwise.
  Map<String, String>? match(String reqMethod, List<String> reqSegments) {
    if (method != '*' && method != reqMethod) return null;
    if (!wildcard && segments.length != reqSegments.length) return null;
    if (wildcard && reqSegments.length < segments.length - 1) return null;
    final params = <String, String>{};
    for (var i = 0; i < segments.length; i++) {
      final seg = segments[i];
      if (seg == '*') {
        params['*'] = reqSegments.skip(i).join('/');
        return params;
      }
      if (seg.startsWith(':')) {
        params[seg.substring(1)] = reqSegments[i];
        continue;
      }
      if (seg != reqSegments[i]) return null;
    }
    return params;
  }
}

/// A high-level HTTP/3 server. Applications register routes and call
/// [bind]; everything QUIC-related is handled internally.
class Http3Server {
  final List<_Route> _routes = <_Route>[];
  Http3AppHandler _fallback = _defaultNotFound;

  QuicServerEndpoint? _endpoint;

  Http3Server();

  // ---------------------------------------------------------------
  // Route registration
  // ---------------------------------------------------------------

  void get(String path, Http3AppHandler handler) => _add('GET', path, handler);
  void post(String path, Http3AppHandler handler) =>
      _add('POST', path, handler);
  void put(String path, Http3AppHandler handler) => _add('PUT', path, handler);
  void delete(String path, Http3AppHandler handler) =>
      _add('DELETE', path, handler);
  void patch(String path, Http3AppHandler handler) =>
      _add('PATCH', path, handler);
  void head(String path, Http3AppHandler handler) =>
      _add('HEAD', path, handler);
  void options(String path, Http3AppHandler handler) =>
      _add('OPTIONS', path, handler);

  /// Match any HTTP method for [path].
  void any(String path, Http3AppHandler handler) => _add('*', path, handler);

  /// Catch-all for requests that no route matched. Default: 404.
  set fallback(Http3AppHandler handler) => _fallback = handler;

  void _add(String method, String path, Http3AppHandler handler) {
    final segments = _splitPath(path);
    final wildcard = segments.isNotEmpty && segments.last == '*';
    _routes.add(_Route(method, segments, handler, wildcard));
  }

  static List<String> _splitPath(String path) {
    final p = path.startsWith('/') ? path.substring(1) : path;
    if (p.isEmpty) return const <String>[];
    return p.split('/');
  }

  // ---------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------

  /// Bind the server to [address]:[port] and begin accepting QUIC
  /// connections. Returns once the UDP socket is open; the returned
  /// future does not complete on its own — call [close] to stop.
  Future<void> bind(dynamic address, int port) async {
    final addr = address is InternetAddress
        ? address
        : InternetAddress(address as String);

    final alpns = AlpnRegistry()..register(Http3ProtocolFactory());

    final ep = await QuicServerEndpoint.bind(
      address: addr,
      port: port,
      alpns: alpns,
    );
    _endpoint = ep;

    ep.connections.listen((conn) {
      final proto = ep.protocol;
      if (proto is Http3ServerProtocol) {
        proto.requestHandler = _dispatch;
      }
    });
  }

  /// Convenience getter — useful for logging.
  InternetAddress? get address => _endpoint?.udp.address;
  int? get port => _endpoint?.udp.port;

  Future<void> close() async {
    final ep = _endpoint;
    if (ep == null) return;
    _endpoint = null;
    await ep.udp.close();
  }

  // ---------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------

  void _dispatch(Http3Request req) {
    final reqSegments = _splitPath(_pathOnly(req.path));
    for (final r in _routes) {
      final params = r.match(req.method, reqSegments);
      if (params != null) {
        _Http3RequestExt(req).params = params;
        _invoke(r.handler, req);
        return;
      }
    }
    _invoke(_fallback, req);
  }

  static String _pathOnly(String p) {
    final q = p.indexOf('?');
    return q < 0 ? p : p.substring(0, q);
  }

  void _invoke(Http3AppHandler h, Http3Request req) {
    try {
      final r = h(req);
      if (r is Future) {
        r.catchError((Object e, StackTrace st) {
          _onError(req, e, st);
        });
      }
    } catch (e, st) {
      _onError(req, e, st);
    }
  }

  void _onError(Http3Request req, Object e, StackTrace st) {
    print('🛑 [http3] handler threw: $e\n$st');
    try {
      req.respond(
        500,
        headers: const <String, String>{
          'content-type': 'text/plain; charset=utf-8',
        },
        body: Uint8List.fromList(utf8.encode('Internal Server Error')),
      );
    } catch (_) {
      /* already responded */
    }
  }
}

void _defaultNotFound(Http3Request req) {
  req.respond(
    404,
    headers: const <String, String>{
      'content-type': 'text/plain; charset=utf-8',
    },
    body: Uint8List.fromList(utf8.encode('Not Found: ${req.path}\n')),
  );
}

// ---------------------------------------------------------------
// Per-request param store + ergonomic extensions
// ---------------------------------------------------------------

final Expando<Map<String, String>> _paramsExpando =
    Expando<Map<String, String>>('http3.params');

class _Http3RequestExt {
  final Http3Request _req;
  _Http3RequestExt(this._req);
  set params(Map<String, String> p) => _paramsExpando[_req] = p;
}

extension Http3RequestApp on Http3Request {
  /// Captured `:name` and `*` route parameters. Empty if the request
  /// matched a static route or the fallback.
  Map<String, String> get params =>
      _paramsExpando[this] ?? const <String, String>{};

  /// Read the request body as a UTF-8 string.
  Future<String> readAsString() async => utf8.decode(await body);

  /// Send a response with a string body, defaulting content-type to
  /// `text/plain; charset=utf-8`.
  void respondText(
    int status,
    String text, {
    Map<String, String> headers = const <String, String>{},
  }) {
    final h = <String, String>{
      'content-type': 'text/plain; charset=utf-8',
      ...headers,
    };
    respond(status, headers: h, body: Uint8List.fromList(utf8.encode(text)));
  }

  /// Send a JSON response (encodes [value] with `dart:convert`).
  void respondJson(
    int status,
    Object? value, {
    Map<String, String> headers = const <String, String>{},
  }) {
    final h = <String, String>{'content-type': 'application/json', ...headers};
    respond(
      status,
      headers: h,
      body: Uint8List.fromList(utf8.encode(jsonEncode(value))),
    );
  }

  /// Send an HTML response.
  void respondHtml(
    int status,
    String html, {
    Map<String, String> headers = const <String, String>{},
  }) {
    final h = <String, String>{
      'content-type': 'text/html; charset=utf-8',
      ...headers,
    };
    respond(status, headers: h, body: Uint8List.fromList(utf8.encode(html)));
  }
}
