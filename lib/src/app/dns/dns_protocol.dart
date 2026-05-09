// DNS-over-QUIC (DoQ, RFC 9250).
//
// Wire format (RFC 9250 §4.2):
//   * Each DNS message is sent on its own bidirectional QUIC stream
//     (one query, one response — the stream is then closed).
//   * On the stream, the DNS message is preceded by a 2-byte
//     big-endian length field (same as DNS-over-TCP, RFC 1035 §4.2.2).
//   * The DNS Message ID SHOULD be 0 (RFC 9250 §4.2.1) — QUIC streams
//     provide the multiplexing.
//
// API:
//   * Server: `DnsOverQuicServerProtocol.queries` — stream of inbound
//     `DnsExchange` objects. Call `exchange.respond(bytes)` to reply.
//   * Client: `DnsOverQuicClientProtocol.query(bytes)` — sends a
//     query on a fresh bidi stream and returns the response bytes.
//
// ALPN: `doq` (RFC 9250 §4.1.1).

import 'dart:async';
import 'dart:typed_data';

import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String doqAlpn = 'doq';

/// One DNS-over-QUIC query/response exchange (server side).
class DnsExchange {
  /// Raw DNS message bytes (no length prefix).
  final Uint8List query;
  final QuicStream _stream;
  bool _replied = false;

  DnsExchange._(this.query, this._stream);

  /// Send the DNS response. Closes the stream (DoQ is one-shot per
  /// stream).
  Future<void> respond(Uint8List response) async {
    if (_replied) {
      throw StateError('DnsExchange already responded');
    }
    _replied = true;
    final out = Uint8List(2 + response.length);
    final bd = ByteData.view(out.buffer);
    bd.setUint16(0, response.length, Endian.big);
    out.setRange(2, out.length, response);
    _stream.write(out);
    await _stream.close();
  }
}

/// Reads a 2-byte big-endian length-prefixed DNS message from a
/// bidi QUIC stream and returns the body. Returns null if the
/// stream closed before a complete message arrived.
Future<Uint8List?> _readOneDnsMessage(QuicStream stream) async {
  final buf = BytesBuilder();
  await for (final chunk in stream.incoming) {
    buf.add(chunk);
    final view = buf.toBytes();
    if (view.length < 2) continue;
    final bd = ByteData.view(view.buffer, view.offsetInBytes, view.length);
    final len = bd.getUint16(0, Endian.big);
    if (view.length < 2 + len) continue;
    return view.sublist(2, 2 + len);
  }
  return null;
}

class DnsOverQuicServerProtocol implements ApplicationProtocol {
  @override
  final String alpn = doqAlpn;
  final QuicConnection conn;
  final StreamController<DnsExchange> _queries =
      StreamController<DnsExchange>();
  StreamSubscription<QuicStream>? _sub;

  DnsOverQuicServerProtocol(this.conn);

  /// Inbound DNS query exchanges. One per accepted bidi stream.
  Stream<DnsExchange> get queries => _queries.stream;

  @override
  Future<void> start() async {
    _sub = conn.incomingStreams.listen((s) async {
      final isUni = (s.id & 0x02) != 0;
      if (isUni) return;
      final body = await _readOneDnsMessage(s);
      if (body == null) return;
      _queries.add(DnsExchange._(body, s));
    });
  }

  @override
  Future<void> stop() async {
    await _sub?.cancel();
    if (!_queries.isClosed) await _queries.close();
  }
}

class DnsOverQuicClientProtocol implements ApplicationProtocol {
  @override
  final String alpn = doqAlpn;
  final QuicConnection conn;
  final Completer<void> _ready = Completer<void>();

  DnsOverQuicClientProtocol(this.conn);

  /// Completes once the protocol is ready to issue queries.
  Future<void> get ready => _ready.future;

  @override
  Future<void> start() async {
    _ready.complete();
  }

  /// Issue one DNS query. Opens a fresh bidi stream, writes the
  /// length-prefixed query, then reads the length-prefixed response.
  Future<Uint8List> query(Uint8List dnsMessage) async {
    final s = await conn.openBidirectionalStream();
    final out = Uint8List(2 + dnsMessage.length);
    final bd = ByteData.view(out.buffer);
    bd.setUint16(0, dnsMessage.length, Endian.big);
    out.setRange(2, out.length, dnsMessage);
    s.write(out);
    final reply = await _readOneDnsMessage(s);
    if (reply == null) {
      throw StateError('DoQ stream closed without a response');
    }
    return reply;
  }

  @override
  Future<void> stop() async {}
}

class DnsOverQuicProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [doqAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      DnsOverQuicServerProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      DnsOverQuicClientProtocol(conn);
}
