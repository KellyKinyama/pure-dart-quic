// WebDAV-over-QUIC.
//
// WebDAV (RFC 4918) is normally carried over HTTP/1.1 or HTTP/2.
// This module ships a minimal "WebDAV-over-QUIC" wire protocol that
// borrows HTTP/WebDAV *semantics* (methods, status codes, headers,
// XML bodies for PROPFIND / PROPPATCH) but uses its own framing on
// top of QUIC streams instead of HTTP/3.
//
// Wire format (one request/response per bidi QUIC stream):
//
//   request  := method:str16 path:str16 nHeaders:u16 (name:str16 value:str16)*
//               body:bytes32
//   response := status:u16 reason:str16 nHeaders:u16 (name:str16 value:str16)*
//               body:bytes32
//
//   str16    := u16 length, then UTF-8 bytes
//   bytes32  := u32 length, then raw bytes
//
// All integers are big-endian. The client opens a fresh bidirectional
// stream per request, writes the request, and half-closes (FIN). The
// server parses the request, dispatches to a [WebDavHandler], writes
// the response, and closes the stream.
//
// API:
//   * [WebDavRequest] / [WebDavResponse] — request/response value types.
//   * [WebDavHandler]                    — server-side request callback.
//   * [WebDavOverQuicServerProtocol]     — exposes `requests` stream and
//                                          `handler` setter; handles per-
//                                          stream framing for callers.
//   * [WebDavOverQuicClientProtocol]     — `request()` issues one WebDAV
//                                          request and returns the response.
//   * [InMemoryWebDavStore]              — small RFC 4918-flavoured backing
//                                          store useful for demos and tests
//                                          (GET, PUT, DELETE, MKCOL, COPY,
//                                          MOVE, OPTIONS, PROPFIND).
//
// ALPN: `webdav-quic`.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String webdavAlpn = 'webdav-quic';

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// A WebDAV request as carried over a single QUIC bidi stream.
class WebDavRequest {
  final String method;
  final String path;
  final Map<String, String> headers;
  final Uint8List body;

  WebDavRequest({
    required this.method,
    required this.path,
    Map<String, String>? headers,
    Uint8List? body,
  }) : headers = headers ?? <String, String>{},
       body = body ?? Uint8List(0);

  @override
  String toString() =>
      'WebDavRequest($method $path, headers=${headers.length}, '
      'body=${body.length}B)';
}

/// A WebDAV response as carried over a single QUIC bidi stream.
class WebDavResponse {
  final int status;
  final String reason;
  final Map<String, String> headers;
  final Uint8List body;

  WebDavResponse({
    required this.status,
    String? reason,
    Map<String, String>? headers,
    Uint8List? body,
  }) : reason = reason ?? _defaultReason(status),
       headers = headers ?? <String, String>{},
       body = body ?? Uint8List(0);

  factory WebDavResponse.text(
    int status,
    String text, {
    Map<String, String>? headers,
  }) {
    final h = <String, String>{
      'content-type': 'text/plain; charset=utf-8',
      ...?headers,
    };
    return WebDavResponse(
      status: status,
      headers: h,
      body: Uint8List.fromList(utf8.encode(text)),
    );
  }

  factory WebDavResponse.xml(
    int status,
    String xml, {
    Map<String, String>? headers,
  }) {
    final h = <String, String>{
      'content-type': 'application/xml; charset=utf-8',
      ...?headers,
    };
    return WebDavResponse(
      status: status,
      headers: h,
      body: Uint8List.fromList(utf8.encode(xml)),
    );
  }

  @override
  String toString() =>
      'WebDavResponse($status $reason, headers=${headers.length}, '
      'body=${body.length}B)';
}

/// Server-side handler signature.
typedef WebDavHandler = FutureOr<WebDavResponse> Function(WebDavRequest req);

String _defaultReason(int status) {
  switch (status) {
    case 200:
      return 'OK';
    case 201:
      return 'Created';
    case 204:
      return 'No Content';
    case 207:
      return 'Multi-Status';
    case 400:
      return 'Bad Request';
    case 403:
      return 'Forbidden';
    case 404:
      return 'Not Found';
    case 405:
      return 'Method Not Allowed';
    case 409:
      return 'Conflict';
    case 412:
      return 'Precondition Failed';
    case 415:
      return 'Unsupported Media Type';
    case 500:
      return 'Internal Server Error';
    case 501:
      return 'Not Implemented';
    case 507:
      return 'Insufficient Storage';
    default:
      return '';
  }
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

Uint8List _encodeRequest(WebDavRequest r) {
  final method = utf8.encode(r.method);
  final path = utf8.encode(r.path);
  final hdrs = <List<int>>[];
  r.headers.forEach((k, v) {
    hdrs.add(utf8.encode(k));
    hdrs.add(utf8.encode(v));
  });
  var size = 2 + method.length + 2 + path.length + 2;
  for (final h in hdrs) {
    size += 2 + h.length;
  }
  size += 4 + r.body.length;

  final out = Uint8List(size);
  final bd = ByteData.view(out.buffer);
  var p = 0;
  p = _writeStr16(out, bd, p, method);
  p = _writeStr16(out, bd, p, path);
  bd.setUint16(p, r.headers.length, Endian.big);
  p += 2;
  for (final h in hdrs) {
    p = _writeStr16(out, bd, p, h);
  }
  bd.setUint32(p, r.body.length, Endian.big);
  p += 4;
  out.setRange(p, p + r.body.length, r.body);
  return out;
}

Uint8List _encodeResponse(WebDavResponse r) {
  final reason = utf8.encode(r.reason);
  final hdrs = <List<int>>[];
  r.headers.forEach((k, v) {
    hdrs.add(utf8.encode(k));
    hdrs.add(utf8.encode(v));
  });
  var size = 2 + 2 + reason.length + 2;
  for (final h in hdrs) {
    size += 2 + h.length;
  }
  size += 4 + r.body.length;

  final out = Uint8List(size);
  final bd = ByteData.view(out.buffer);
  var p = 0;
  bd.setUint16(p, r.status, Endian.big);
  p += 2;
  p = _writeStr16(out, bd, p, reason);
  bd.setUint16(p, r.headers.length, Endian.big);
  p += 2;
  for (final h in hdrs) {
    p = _writeStr16(out, bd, p, h);
  }
  bd.setUint32(p, r.body.length, Endian.big);
  p += 4;
  out.setRange(p, p + r.body.length, r.body);
  return out;
}

int _writeStr16(Uint8List out, ByteData bd, int p, List<int> bytes) {
  bd.setUint16(p, bytes.length, Endian.big);
  p += 2;
  out.setRange(p, p + bytes.length, bytes);
  return p + bytes.length;
}

WebDavRequest _decodeRequest(Uint8List buf) {
  final bd = ByteData.view(buf.buffer, buf.offsetInBytes, buf.length);
  var p = 0;
  final method = _readStr16(buf, bd, (np) => p = np, p);
  final path = _readStr16(buf, bd, (np) => p = np, p);
  final n = bd.getUint16(p, Endian.big);
  p += 2;
  final headers = <String, String>{};
  for (var i = 0; i < n; i++) {
    final k = _readStr16(buf, bd, (np) => p = np, p);
    final v = _readStr16(buf, bd, (np) => p = np, p);
    headers[k] = v;
  }
  final blen = bd.getUint32(p, Endian.big);
  p += 4;
  final body = Uint8List.fromList(buf.sublist(p, p + blen));
  return WebDavRequest(
    method: method,
    path: path,
    headers: headers,
    body: body,
  );
}

WebDavResponse _decodeResponse(Uint8List buf) {
  final bd = ByteData.view(buf.buffer, buf.offsetInBytes, buf.length);
  var p = 0;
  final status = bd.getUint16(p, Endian.big);
  p += 2;
  final reason = _readStr16(buf, bd, (np) => p = np, p);
  final n = bd.getUint16(p, Endian.big);
  p += 2;
  final headers = <String, String>{};
  for (var i = 0; i < n; i++) {
    final k = _readStr16(buf, bd, (np) => p = np, p);
    final v = _readStr16(buf, bd, (np) => p = np, p);
    headers[k] = v;
  }
  final blen = bd.getUint32(p, Endian.big);
  p += 4;
  final body = Uint8List.fromList(buf.sublist(p, p + blen));
  return WebDavResponse(
    status: status,
    reason: reason,
    headers: headers,
    body: body,
  );
}

String _readStr16(Uint8List buf, ByteData bd, void Function(int) setP, int p) {
  final len = bd.getUint16(p, Endian.big);
  p += 2;
  final s = utf8.decode(buf.sublist(p, p + len));
  setP(p + len);
  return s;
}

/// Drain a stream's incoming bytes until FIN, returning the full payload.
Future<Uint8List> _drain(QuicStream s) async {
  final b = BytesBuilder(copy: false);
  await for (final chunk in s.incoming) {
    b.add(chunk);
  }
  return b.toBytes();
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

abstract class _WebDavBase implements ApplicationProtocol {
  @override
  final String alpn = webdavAlpn;
  final QuicConnection conn;

  _WebDavBase(this.conn);

  @override
  Future<void> stop() async {}
}

/// Server-side WebDAV-over-QUIC protocol. Each inbound bidi stream is
/// treated as a single request/response exchange.
class WebDavOverQuicServerProtocol extends _WebDavBase {
  StreamSubscription<QuicStream>? _sub;
  final StreamController<WebDavRequest> _requests =
      StreamController<WebDavRequest>.broadcast();

  /// Optional handler. If set, the server replies automatically using
  /// the handler's result. If left null, callers can subscribe to
  /// [requests] and reply manually via [reply].
  WebDavHandler? handler;

  final Map<int, QuicStream> _pending = <int, QuicStream>{};

  WebDavOverQuicServerProtocol(super.conn);

  /// Inbound parsed WebDAV requests (after FIN). Use [reply] to answer.
  Stream<WebDavRequest> get requests => _requests.stream;

  @override
  Future<void> start() async {
    _sub = conn.incomingStreams.listen((s) {
      final isUni = (s.id & 0x02) != 0;
      if (isUni) return;
      _serve(s);
    });
  }

  Future<void> _serve(QuicStream s) async {
    try {
      final raw = await _drain(s);
      final req = _decodeRequest(raw);
      _pending[s.id] = s;
      _requests.add(req);
      final h = handler;
      if (h != null) {
        final resp = await h(req);
        await _writeResponse(s.id, resp);
      }
    } catch (e) {
      try {
        final stream = _pending.remove(s.id) ?? s;
        stream.write(
          _encodeResponse(
            WebDavResponse.text(400, 'Malformed WebDAV-over-QUIC request: $e'),
          ),
        );
        await stream.close();
      } catch (_) {
        /* ignore */
      }
    }
  }

  /// Send a response on a previously received request stream. Used by
  /// callers consuming [requests] manually. Streams are matched in
  /// arrival order; if the caller responds out of order they should
  /// instead set a [handler].
  Future<void> reply(WebDavRequest req, WebDavResponse resp) async {
    if (_pending.isEmpty) {
      throw StateError('reply() called with no pending request stream');
    }
    final id = _pending.keys.first;
    await _writeResponse(id, resp);
  }

  Future<void> _writeResponse(int streamId, WebDavResponse resp) async {
    final s = _pending.remove(streamId);
    if (s == null) return;
    s.write(_encodeResponse(resp));
    await s.close();
  }

  @override
  Future<void> stop() async {
    await _sub?.cancel();
    if (!_requests.isClosed) await _requests.close();
    await super.stop();
  }
}

/// Client-side WebDAV-over-QUIC protocol. Use [request] (or the
/// convenience helpers) to dispatch a request and read its response.
class WebDavOverQuicClientProtocol extends _WebDavBase {
  WebDavOverQuicClientProtocol(super.conn);

  @override
  Future<void> start() async {
    /* no bootstrap */
  }

  /// Issue a WebDAV request on a fresh bidi stream and return the
  /// server's response.
  Future<WebDavResponse> request(WebDavRequest req) async {
    final s = await conn.openBidirectionalStream();
    s.write(_encodeRequest(req));
    await s.close(); // FIN: signals end of request body
    final raw = await _drain(s);
    return _decodeResponse(raw);
  }

  Future<WebDavResponse> options(String path) =>
      request(WebDavRequest(method: 'OPTIONS', path: path));

  Future<WebDavResponse> get(String path) =>
      request(WebDavRequest(method: 'GET', path: path));

  Future<WebDavResponse> put(
    String path,
    Uint8List body, {
    String? contentType,
  }) => request(
    WebDavRequest(
      method: 'PUT',
      path: path,
      headers: {'content-type': ?contentType},
      body: body,
    ),
  );

  Future<WebDavResponse> delete(String path) =>
      request(WebDavRequest(method: 'DELETE', path: path));

  Future<WebDavResponse> mkcol(String path) =>
      request(WebDavRequest(method: 'MKCOL', path: path));

  Future<WebDavResponse> copy(
    String path,
    String destination, {
    bool overwrite = true,
  }) => request(
    WebDavRequest(
      method: 'COPY',
      path: path,
      headers: {'destination': destination, 'overwrite': overwrite ? 'T' : 'F'},
    ),
  );

  Future<WebDavResponse> move(
    String path,
    String destination, {
    bool overwrite = true,
  }) => request(
    WebDavRequest(
      method: 'MOVE',
      path: path,
      headers: {'destination': destination, 'overwrite': overwrite ? 'T' : 'F'},
    ),
  );

  /// PROPFIND with the given depth (`0`, `1`, or `infinity`). The body
  /// is a standard WebDAV `<propfind><allprop/></propfind>` document by
  /// default.
  Future<WebDavResponse> propfind(
    String path, {
    String depth = '1',
    String? body,
  }) {
    final xml =
        body ??
        '<?xml version="1.0" encoding="utf-8"?>'
            '<propfind xmlns="DAV:"><allprop/></propfind>';
    return request(
      WebDavRequest(
        method: 'PROPFIND',
        path: path,
        headers: {
          'depth': depth,
          'content-type': 'application/xml; charset=utf-8',
        },
        body: Uint8List.fromList(utf8.encode(xml)),
      ),
    );
  }
}

class WebDavOverQuicProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [webdavAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      WebDavOverQuicServerProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      WebDavOverQuicClientProtocol(conn);
}

// ---------------------------------------------------------------------------
// In-memory WebDAV store (demo / test backing)
// ---------------------------------------------------------------------------

/// Minimal in-memory WebDAV store usable as a [WebDavHandler]. It
/// supports the core RFC 4918 verbs (GET, PUT, DELETE, MKCOL, COPY,
/// MOVE, OPTIONS, PROPFIND) over a single namespace rooted at `/`.
///
/// Not thread-safe; intended for single-connection demos and tests.
class InMemoryWebDavStore {
  /// Files keyed by canonicalised path. Value = body bytes.
  final Map<String, Uint8List> _files = <String, Uint8List>{};

  /// Collection (directory) paths. Always contains `/`.
  final Set<String> _collections = <String>{'/'};

  /// Per-resource content types.
  final Map<String, String> _contentTypes = <String, String>{};

  WebDavHandler get handler => _dispatch;

  FutureOr<WebDavResponse> _dispatch(WebDavRequest r) {
    final path = _canonical(r.path);
    switch (r.method.toUpperCase()) {
      case 'OPTIONS':
        return WebDavResponse(
          status: 200,
          headers: {
            'dav': '1',
            'allow': 'OPTIONS, GET, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND',
          },
        );
      case 'GET':
        return _get(path);
      case 'PUT':
        return _put(path, r);
      case 'DELETE':
        return _delete(path);
      case 'MKCOL':
        return _mkcol(path);
      case 'COPY':
        return _copyOrMove(path, r, move: false);
      case 'MOVE':
        return _copyOrMove(path, r, move: true);
      case 'PROPFIND':
        return _propfind(path, r);
      default:
        return WebDavResponse.text(405, 'Method Not Allowed: ${r.method}');
    }
  }

  WebDavResponse _get(String path) {
    final file = _files[path];
    if (file == null) {
      if (_collections.contains(path)) {
        return WebDavResponse.text(
          200,
          'Collection ${path == '/' ? '/' : path}\n',
        );
      }
      return WebDavResponse.text(404, 'Not Found');
    }
    final ct = _contentTypes[path] ?? 'application/octet-stream';
    return WebDavResponse(
      status: 200,
      headers: {'content-type': ct, 'content-length': file.length.toString()},
      body: file,
    );
  }

  WebDavResponse _put(String path, WebDavRequest r) {
    if (_collections.contains(path)) {
      return WebDavResponse.text(405, 'Cannot PUT onto collection');
    }
    final parent = _parent(path);
    if (!_collections.contains(parent)) {
      return WebDavResponse.text(409, 'Parent collection missing: $parent');
    }
    final created = !_files.containsKey(path);
    _files[path] = Uint8List.fromList(r.body);
    final ct = r.headers['content-type'];
    if (ct != null) _contentTypes[path] = ct;
    return WebDavResponse(status: created ? 201 : 204);
  }

  WebDavResponse _delete(String path) {
    if (path == '/') {
      return WebDavResponse.text(403, 'Cannot delete root');
    }
    if (_files.remove(path) != null) {
      _contentTypes.remove(path);
      return WebDavResponse(status: 204);
    }
    if (_collections.remove(path)) {
      // remove descendants
      _files.removeWhere((k, _) => k.startsWith('$path/'));
      _collections.removeWhere((k) => k.startsWith('$path/'));
      _contentTypes.removeWhere((k, _) => k.startsWith('$path/'));
      return WebDavResponse(status: 204);
    }
    return WebDavResponse.text(404, 'Not Found');
  }

  WebDavResponse _mkcol(String path) {
    if (path == '/') {
      return WebDavResponse.text(405, 'Root already exists');
    }
    if (_collections.contains(path) || _files.containsKey(path)) {
      return WebDavResponse.text(405, 'Resource already exists');
    }
    final parent = _parent(path);
    if (!_collections.contains(parent)) {
      return WebDavResponse.text(409, 'Parent collection missing: $parent');
    }
    _collections.add(path);
    return WebDavResponse(status: 201);
  }

  WebDavResponse _copyOrMove(
    String src,
    WebDavRequest r, {
    required bool move,
  }) {
    final destRaw = r.headers['destination'];
    if (destRaw == null) {
      return WebDavResponse.text(400, 'Missing Destination header');
    }
    final dest = _canonical(_stripAuthority(destRaw));
    final overwrite = (r.headers['overwrite'] ?? 'T').toUpperCase() != 'F';
    final destExists = _files.containsKey(dest) || _collections.contains(dest);
    if (destExists && !overwrite) {
      return WebDavResponse.text(412, 'Destination exists');
    }
    if (_files.containsKey(src)) {
      _files[dest] = Uint8List.fromList(_files[src]!);
      final ct = _contentTypes[src];
      if (ct != null) _contentTypes[dest] = ct;
      if (move) {
        _files.remove(src);
        _contentTypes.remove(src);
      }
      return WebDavResponse(status: destExists ? 204 : 201);
    }
    if (_collections.contains(src)) {
      _collections.add(dest);
      if (move) _collections.remove(src);
      return WebDavResponse(status: destExists ? 204 : 201);
    }
    return WebDavResponse.text(404, 'Not Found');
  }

  WebDavResponse _propfind(String path, WebDavRequest r) {
    final exists = _files.containsKey(path) || _collections.contains(path);
    if (!exists) return WebDavResponse.text(404, 'Not Found');
    final depth = r.headers['depth'] ?? '1';
    final entries = <String>[path];
    if (_collections.contains(path) && depth != '0') {
      for (final f in _files.keys) {
        if (_parent(f) == path) entries.add(f);
      }
      for (final c in _collections) {
        if (c != path && _parent(c) == path) entries.add(c);
      }
    }
    final sb = StringBuffer()
      ..write('<?xml version="1.0" encoding="utf-8"?>')
      ..write('<multistatus xmlns="DAV:">');
    for (final href in entries) {
      final isCol = _collections.contains(href);
      final size = isCol ? 0 : (_files[href]?.length ?? 0);
      sb
        ..write('<response>')
        ..write('<href>${_xml(href)}</href>')
        ..write('<propstat><prop>')
        ..write(
          isCol
              ? '<resourcetype><collection/></resourcetype>'
              : '<resourcetype/>',
        )
        ..write('<getcontentlength>$size</getcontentlength>')
        ..write('</prop><status>HTTP/1.1 200 OK</status></propstat>')
        ..write('</response>');
    }
    sb.write('</multistatus>');
    return WebDavResponse.xml(207, sb.toString());
  }

  // ----- helpers ---------------------------------------------------------

  static String _canonical(String p) {
    if (p.isEmpty) return '/';
    var s = p.startsWith('/') ? p : '/$p';
    if (s.length > 1 && s.endsWith('/')) s = s.substring(0, s.length - 1);
    return s;
  }

  static String _parent(String p) {
    if (p == '/' || p.isEmpty) return '/';
    final i = p.lastIndexOf('/');
    if (i <= 0) return '/';
    return p.substring(0, i);
  }

  static String _stripAuthority(String dest) {
    final scheme = dest.indexOf('://');
    if (scheme < 0) return dest;
    final slash = dest.indexOf('/', scheme + 3);
    return slash < 0 ? '/' : dest.substring(slash);
  }

  static String _xml(String s) => s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;');
}
