// WebDAV over HTTP/3.
//
// This module reuses the WebDAV semantics from `webdav_protocol.dart`
// (the [WebDavRequest] / [WebDavResponse] / [WebDavHandler] /
// [InMemoryWebDavStore] types) but carries them on top of the standard
// HTTP/3 server in [Http3Server] instead of the bespoke length-prefixed
// framing used by the `webdav-quic` ALPN.
//
// Because this speaks real HTTP/3 with the `h3` ALPN, any HTTP/3 client
// that supports WebDAV verbs can mount the resulting namespace — in
// particular, this repo's own [Http3ClientProtocol] (see
// [WebDavHttp3Client]) and any future browser / OS WebDAV-over-H3
// client.
//
// Verbs supported: OPTIONS, GET, PUT, DELETE, MKCOL, COPY, MOVE,
// PROPFIND. (The `Http3Server` router uses `req.method` verbatim, so
// custom WebDAV verbs flow through unchanged.)

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../h3/h3_protocol.dart';
import '../h3/http3_server.dart';
import 'webdav_protocol.dart';

/// HTTP/3 server that exposes a [WebDavHandler] (typically backed by
/// [InMemoryWebDavStore]) under the `h3` ALPN.
///
/// Example:
/// ```dart
/// final dav = WebDavHttp3Server(InMemoryWebDavStore().handler);
/// await dav.bind('127.0.0.1', 4439);
/// ```
class WebDavHttp3Server {
  final Http3Server _h3 = Http3Server();
  final WebDavHandler _handler;

  /// If true (default), the server emits a brief log line for every
  /// inbound WebDAV request. Set to false to silence it.
  bool logRequests;

  WebDavHttp3Server(this._handler, {this.logRequests = true}) {
    _h3.any('/*', _onRequest);
    _h3.any('/', _onRequest);
  }

  /// Bind the underlying HTTP/3 server.
  Future<void> bind(dynamic address, int port) => _h3.bind(address, port);

  Future<void> close() => _h3.close();

  InternetAddress? get address => _h3.address;
  int? get port => _h3.port;

  Future<void> _onRequest(Http3Request req) async {
    final body = await req.body;
    final headers = <String, String>{};
    req.headers.forEach((k, v) {
      // Drop HTTP/3 pseudo-headers; expose only normal request headers
      // to the WebDAV handler.
      if (k.startsWith(':')) return;
      headers[k.toLowerCase()] = v;
    });

    if (logRequests) {
      print(
        '▶ [webdav/h3] ${req.method} ${req.path} '
        '(${body.length}B headers=${headers.length})',
      );
    }

    final davReq = WebDavRequest(
      method: req.method,
      path: req.path,
      headers: headers,
      body: body,
    );

    final res = await _handler(davReq);
    final outHeaders = <String, String>{};
    res.headers.forEach((k, v) => outHeaders[k.toLowerCase()] = v);
    outHeaders.putIfAbsent('content-length', () => res.body.length.toString());
    req.respond(res.status, headers: outHeaders, body: res.body);
  }
}

/// Convenience client wrapper around [Http3ClientProtocol] that issues
/// WebDAV verbs (GET, PUT, DELETE, MKCOL, COPY, MOVE, OPTIONS,
/// PROPFIND) and decodes responses into [WebDavResponse].
class WebDavHttp3Client {
  final Http3ClientProtocol _h3;

  WebDavHttp3Client(this._h3);

  Future<WebDavResponse> options(String path) => _send('OPTIONS', path);

  Future<WebDavResponse> get(String path) => _send('GET', path);

  Future<WebDavResponse> put(
    String path,
    Uint8List body, {
    String? contentType,
  }) {
    final h = <String, String>{};
    if (contentType != null) h['content-type'] = contentType;
    return _send('PUT', path, headers: h, body: body);
  }

  Future<WebDavResponse> delete(String path) => _send('DELETE', path);

  Future<WebDavResponse> mkcol(String path) => _send('MKCOL', path);

  Future<WebDavResponse> copy(
    String path,
    String destination, {
    bool overwrite = true,
  }) => _send(
    'COPY',
    path,
    headers: {'destination': destination, 'overwrite': overwrite ? 'T' : 'F'},
  );

  Future<WebDavResponse> move(
    String path,
    String destination, {
    bool overwrite = true,
  }) => _send(
    'MOVE',
    path,
    headers: {'destination': destination, 'overwrite': overwrite ? 'T' : 'F'},
  );

  Future<WebDavResponse> propfind(
    String path, {
    String depth = '1',
    String? body,
  }) {
    final xml =
        body ??
        '<?xml version="1.0" encoding="utf-8"?>'
            '<propfind xmlns="DAV:"><allprop/></propfind>';
    return _send(
      'PROPFIND',
      path,
      headers: {
        'depth': depth,
        'content-type': 'application/xml; charset=utf-8',
      },
      body: Uint8List.fromList(utf8.encode(xml)),
    );
  }

  Future<WebDavResponse> _send(
    String method,
    String path, {
    Map<String, String> headers = const <String, String>{},
    Uint8List? body,
  }) async {
    final r = await _h3.request(method, path, headers: headers, body: body);
    final outHeaders = <String, String>{};
    r.headers.forEach((k, v) {
      if (k.startsWith(':')) return;
      outHeaders[k.toLowerCase()] = v;
    });
    return WebDavResponse(status: r.status, headers: outHeaders, body: r.body);
  }
}
