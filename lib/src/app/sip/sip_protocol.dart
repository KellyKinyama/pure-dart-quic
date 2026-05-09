// SIP-over-QUIC (draft-hurst-sip-quic style).
//
// Wire format:
//   * One bidirectional QUIC stream per SIP transaction. The
//     initiator opens the stream, writes one full SIP request
//     (start-line + headers + CRLF + body), the peer writes one or
//     more SIP responses on the same stream, and the stream closes.
//   * On the wire each SIP message uses RFC 3261 §7 framing:
//         <start-line> CRLF
//         <header>: <value> CRLF
//         …
//         CRLF
//         <body of Content-Length octets>
//     Header field continuations (a line beginning with SP/HTAB) are
//     unfolded into the previous header value per RFC 3261 §7.3.1.
//
// API:
//   * `SipMessage` — request *or* response, with a case-insensitive
//     header map, `body` bytes, and a [`SipMessage.encode`] helper
//     that writes the canonical wire form back out.
//   * `SipOverQuicServerProtocol.transactions` — stream of inbound
//     `SipTransaction(request, stream)`. Call
//     `transaction.respond(response)` to write a response.
//   * `SipOverQuicClientProtocol.send(request)` — open a fresh bidi
//     stream, write the request, return a `Stream<SipMessage>` of
//     responses.
//
// API shape inspired by KellyKinyama/dart-pbx; the parser is a fresh
// minimal RFC 3261 implementation (no dialog/registrar/SDP state —
// build those on top of these messages).
//
// ALPN: `sip` (provisional; no IETF registration yet).

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String sipAlpn = 'sip';

/// Direction of a SIP message.
enum SipMessageKind { request, response }

/// A SIP request or response, decoded into its high-level pieces.
///
/// The header list preserves wire order. Lookups via [header] /
/// [headerAll] are case-insensitive. Multiple occurrences of the
/// same header (Via, Route, Record-Route, Contact, …) are kept.
class SipMessage {
  final SipMessageKind kind;

  // Request fields.
  final String? method; // e.g. "INVITE", "REGISTER"
  final String? requestUri; // e.g. "sip:bob@example.com"

  // Response fields.
  final int? statusCode; // e.g. 200, 401, 486
  final String? reasonPhrase; // e.g. "OK"

  // Common to both.
  final String version; // e.g. "SIP/2.0"
  final List<MapEntry<String, String>> headers;
  final Uint8List body;

  SipMessage._({
    required this.kind,
    this.method,
    this.requestUri,
    this.statusCode,
    this.reasonPhrase,
    required this.version,
    required this.headers,
    required this.body,
  });

  factory SipMessage.request({
    required String method,
    required String requestUri,
    String version = 'SIP/2.0',
    List<MapEntry<String, String>> headers = const [],
    Uint8List? body,
  }) {
    return SipMessage._(
      kind: SipMessageKind.request,
      method: method,
      requestUri: requestUri,
      version: version,
      headers: List.of(headers),
      body: body ?? Uint8List(0),
    );
  }

  factory SipMessage.response({
    required int statusCode,
    required String reasonPhrase,
    String version = 'SIP/2.0',
    List<MapEntry<String, String>> headers = const [],
    Uint8List? body,
  }) {
    return SipMessage._(
      kind: SipMessageKind.response,
      statusCode: statusCode,
      reasonPhrase: reasonPhrase,
      version: version,
      headers: List.of(headers),
      body: body ?? Uint8List(0),
    );
  }

  /// First value for [name] (case-insensitive) or null.
  String? header(String name) {
    final lc = name.toLowerCase();
    for (final h in headers) {
      if (h.key.toLowerCase() == lc) return h.value;
    }
    return null;
  }

  /// All values for [name] (case-insensitive), in wire order.
  List<String> headerAll(String name) {
    final lc = name.toLowerCase();
    return [
      for (final h in headers)
        if (h.key.toLowerCase() == lc) h.value,
    ];
  }

  /// Encode to the canonical RFC 3261 wire form (start-line CRLF
  /// headers CRLF CRLF body). Adds / overwrites Content-Length to
  /// match `body.length`.
  Uint8List encode() {
    final sb = StringBuffer();
    if (kind == SipMessageKind.request) {
      sb.write('$method $requestUri $version\r\n');
    } else {
      sb.write('$version $statusCode $reasonPhrase\r\n');
    }
    var sawCl = false;
    for (final h in headers) {
      if (h.key.toLowerCase() == 'content-length') {
        sawCl = true;
        sb.write('Content-Length: ${body.length}\r\n');
      } else {
        sb.write('${h.key}: ${h.value}\r\n');
      }
    }
    if (!sawCl) sb.write('Content-Length: ${body.length}\r\n');
    sb.write('\r\n');
    final headerBytes = utf8.encode(sb.toString());
    final out = Uint8List(headerBytes.length + body.length);
    out.setRange(0, headerBytes.length, headerBytes);
    out.setRange(headerBytes.length, out.length, body);
    return out;
  }

  @override
  String toString() {
    if (kind == SipMessageKind.request) {
      return 'SipMessage($method $requestUri ${headers.length} hdrs '
          'body=${body.length}B)';
    }
    return 'SipMessage($statusCode $reasonPhrase ${headers.length} hdrs '
        'body=${body.length}B)';
  }
}

/// One SIP message + the QUIC stream it arrived on. The peer can
/// respond by calling [respond]; multiple responses are allowed
/// (1xx provisional responses → one final ≥200).
class SipTransaction {
  final SipMessage request;
  final QuicStream stream;
  bool _final = false;
  SipTransaction(this.request, this.stream);

  /// Write one response on the same stream. After a final (≥200)
  /// response the stream's write half is closed.
  Future<void> respond(SipMessage response) async {
    if (response.kind != SipMessageKind.response) {
      throw ArgumentError('respond() requires a response message');
    }
    if (_final) throw StateError('Final response already sent');
    stream.write(response.encode());
    if ((response.statusCode ?? 0) >= 200) {
      _final = true;
      await stream.close();
    }
  }
}

/// Returns a stream of fully-parsed [SipMessage]s decoded from a byte
/// stream of concatenated SIP messages.
Stream<SipMessage> decodeSipMessages(Stream<Uint8List> source) async* {
  final buf = BytesBuilder();
  await for (final chunk in source) {
    buf.add(chunk);
    while (true) {
      final view = buf.toBytes();
      final parsed = _tryParseOne(view);
      if (parsed == null) break;
      yield parsed.message;
      final tail = view.sublist(parsed.consumed);
      buf
        ..clear()
        ..add(tail);
    }
  }
}

({SipMessage message, int consumed})? _tryParseOne(Uint8List data) {
  // Find the header/body delimiter (CRLFCRLF).
  var headerEnd = -1;
  for (var i = 0; i + 3 < data.length; i++) {
    if (data[i] == 0x0d &&
        data[i + 1] == 0x0a &&
        data[i + 2] == 0x0d &&
        data[i + 3] == 0x0a) {
      headerEnd = i;
      break;
    }
  }
  if (headerEnd < 0) return null;

  final headerStr = utf8.decode(data.sublist(0, headerEnd));
  final lines = _unfoldHeaders(headerStr.split('\r\n'));
  if (lines.isEmpty) {
    throw FormatException('SIP message has no start-line');
  }
  final startLine = lines.first;
  final headers = <MapEntry<String, String>>[];
  for (final line in lines.skip(1)) {
    if (line.isEmpty) continue;
    final colon = line.indexOf(':');
    if (colon < 0) {
      throw FormatException('SIP header missing colon: "$line"');
    }
    final name = line.substring(0, colon).trim();
    var value = line.substring(colon + 1);
    if (value.isNotEmpty && (value[0] == ' ' || value[0] == '\t')) {
      value = value.substring(1);
    }
    headers.add(MapEntry(name, value.trimRight()));
  }

  // Content-Length is mandatory for stream-oriented SIP transports
  // (RFC 3261 §18.3 / §7.5).
  var contentLength = 0;
  for (final h in headers) {
    if (h.key.toLowerCase() == 'content-length') {
      contentLength = int.parse(h.value.trim());
      break;
    }
  }
  final bodyStart = headerEnd + 4;
  if (data.length < bodyStart + contentLength) return null;
  final body = Uint8List.fromList(
    data.sublist(bodyStart, bodyStart + contentLength),
  );

  final SipMessage msg;
  if (startLine.startsWith('SIP/')) {
    // Status line: "SIP/2.0 200 OK"
    final sp1 = startLine.indexOf(' ');
    final sp2 = startLine.indexOf(' ', sp1 + 1);
    if (sp1 < 0 || sp2 < 0) {
      throw FormatException('Malformed SIP status line: "$startLine"');
    }
    msg = SipMessage.response(
      version: startLine.substring(0, sp1),
      statusCode: int.parse(startLine.substring(sp1 + 1, sp2)),
      reasonPhrase: startLine.substring(sp2 + 1),
      headers: headers,
      body: body,
    );
  } else {
    // Request line: "INVITE sip:bob@x SIP/2.0"
    final sp1 = startLine.indexOf(' ');
    final sp2 = startLine.lastIndexOf(' ');
    if (sp1 < 0 || sp2 <= sp1) {
      throw FormatException('Malformed SIP request line: "$startLine"');
    }
    msg = SipMessage.request(
      method: startLine.substring(0, sp1),
      requestUri: startLine.substring(sp1 + 1, sp2),
      version: startLine.substring(sp2 + 1),
      headers: headers,
      body: body,
    );
  }

  return (message: msg, consumed: bodyStart + contentLength);
}

/// Apply RFC 3261 §7.3.1 line unfolding: a line beginning with SP or
/// HTAB is appended (with a single space) to the previous line.
List<String> _unfoldHeaders(List<String> raw) {
  final out = <String>[];
  for (final line in raw) {
    if (line.isEmpty) {
      out.add(line);
      continue;
    }
    final c = line.codeUnitAt(0);
    if ((c == 0x20 || c == 0x09) && out.isNotEmpty) {
      out[out.length - 1] = '${out.last} ${line.trim()}';
    } else {
      out.add(line);
    }
  }
  return out;
}

class SipOverQuicServerProtocol implements ApplicationProtocol {
  @override
  final String alpn = sipAlpn;
  final QuicConnection conn;
  final StreamController<SipTransaction> _transactions =
      StreamController<SipTransaction>.broadcast();
  StreamSubscription<QuicStream>? _sub;

  SipOverQuicServerProtocol(this.conn);

  /// Inbound SIP transactions. One per accepted bidi stream; the
  /// emitted [SipTransaction] carries the parsed request and the
  /// stream to write responses on.
  Stream<SipTransaction> get transactions => _transactions.stream;

  @override
  Future<void> start() async {
    _sub = conn.incomingStreams.listen((s) async {
      final isUni = (s.id & 0x02) != 0;
      if (isUni) return;
      // Read exactly one request, then surface it as a transaction.
      final iter = StreamIterator<SipMessage>(decodeSipMessages(s.incoming));
      if (!await iter.moveNext()) return;
      final req = iter.current;
      await iter.cancel();
      if (req.kind != SipMessageKind.request) return;
      _transactions.add(SipTransaction(req, s));
    });
  }

  @override
  Future<void> stop() async {
    await _sub?.cancel();
    if (!_transactions.isClosed) await _transactions.close();
  }
}

class SipOverQuicClientProtocol implements ApplicationProtocol {
  @override
  final String alpn = sipAlpn;
  final QuicConnection conn;
  final Completer<void> _ready = Completer<void>();

  SipOverQuicClientProtocol(this.conn);

  /// Completes once the protocol is ready to send requests.
  Future<void> get ready => _ready.future;

  @override
  Future<void> start() async {
    _ready.complete();
  }

  /// Open a fresh bidi stream, write [request], and surface the
  /// stream of responses (provisional 1xx + final).
  Future<Stream<SipMessage>> send(SipMessage request) async {
    if (request.kind != SipMessageKind.request) {
      throw ArgumentError('send() requires a request message');
    }
    final s = await conn.openBidirectionalStream();
    s.write(request.encode());
    return decodeSipMessages(s.incoming);
  }

  @override
  Future<void> stop() async {}
}

class SipOverQuicProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [sipAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      SipOverQuicServerProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      SipOverQuicClientProtocol(conn);
}
