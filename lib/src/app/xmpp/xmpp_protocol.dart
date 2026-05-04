// XMPP-over-QUIC (draft-moffitt-xmpp-over-quic style).
//
// Wire format:
//   * One bidirectional QUIC stream per XMPP client connection
//     (the "XMPP stream"). The client opens it; the server accepts
//     the first inbound bidi stream as the XMPP stream.
//   * Stanzas are framed length-prefixed: 4-byte big-endian uint
//     followed by the UTF-8 XML stanza body. This deviates from
//     traditional XMPP (which streams XML continuously) but matches
//     the common length-prefixed framing recommended by recent
//     I-Ds and is trivial to parse without a streaming XML parser.
//   * QUIC already provides TLS, so STARTTLS / SASL EXTERNAL would
//     normally take over from there — those are out of scope for
//     this demo module.
//
// API:
//   * `XmppOverQuicConnection.stanzas` — inbound stanza stream.
//   * `XmppOverQuicConnection.send(String stanza)` — send a stanza.
//   * `XmppOverQuicConnection.opened` — completes once the underlying
//     bidi stream is established (server: first inbound; client: the
//     opened outbound stream).
//
// ALPN: `xmpp-quic`.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String xmppAlpn = 'xmpp-quic';

/// A logical XMPP-over-QUIC stream multiplexed onto a single bidi
/// QUIC stream. Owns its own stanza-framing state.
class XmppOverQuicConnection {
  final QuicStream stream;
  final StreamController<String> _stanzas = StreamController<String>();

  final BytesBuilder _buf = BytesBuilder();
  StreamSubscription<Uint8List>? _sub;

  XmppOverQuicConnection._(this.stream) {
    _sub = stream.incoming.listen(
      _onChunk,
      onDone: () {
        if (!_stanzas.isClosed) _stanzas.close();
      },
    );
  }

  /// Inbound XMPP stanzas (full UTF-8 string per stanza).
  Stream<String> get stanzas => _stanzas.stream;

  /// Send one stanza. Adds the 4-byte length prefix and writes it
  /// to the underlying QUIC stream.
  void send(String stanza) {
    final body = utf8.encode(stanza);
    final out = Uint8List(4 + body.length);
    final bd = ByteData.view(out.buffer);
    bd.setUint32(0, body.length, Endian.big);
    out.setRange(4, out.length, body);
    stream.write(out);
  }

  Future<void> close() async {
    await _sub?.cancel();
    if (!_stanzas.isClosed) await _stanzas.close();
    await stream.close();
  }

  void _onChunk(Uint8List chunk) {
    _buf.add(chunk);
    while (true) {
      final view = _buf.toBytes();
      if (view.length < 4) return;
      final bd = ByteData.view(view.buffer, view.offsetInBytes, view.length);
      final len = bd.getUint32(0, Endian.big);
      if (view.length < 4 + len) return;
      final body = view.sublist(4, 4 + len);
      final stanza = utf8.decode(body);
      _stanzas.add(stanza);
      final tail = view.sublist(4 + len);
      _buf
        ..clear()
        ..add(tail);
    }
  }
}

abstract class _XmppBase implements ApplicationProtocol {
  @override
  final String alpn = xmppAlpn;
  final QuicConnection conn;
  final Completer<XmppOverQuicConnection> _xmpp =
      Completer<XmppOverQuicConnection>();

  _XmppBase(this.conn);

  /// Completes once the XMPP bidi stream is bound (server: accepted;
  /// client: opened).
  Future<XmppOverQuicConnection> get opened => _xmpp.future;

  @override
  Future<void> stop() async {
    if (_xmpp.isCompleted) {
      final c = await _xmpp.future;
      await c.close();
    }
  }
}

class XmppOverQuicServerProtocol extends _XmppBase {
  StreamSubscription<QuicStream>? _sub;
  XmppOverQuicServerProtocol(super.conn);

  @override
  Future<void> start() async {
    _sub = conn.incomingStreams.listen((s) {
      // Take the first inbound *bidi* stream as the XMPP stream.
      final isUni = (s.id & 0x02) != 0;
      if (isUni) return;
      if (_xmpp.isCompleted) return;
      print('✅ [xmpp] accepted stream id=${s.id}');
      _xmpp.complete(XmppOverQuicConnection._(s));
    });
  }

  @override
  Future<void> stop() async {
    await _sub?.cancel();
    await super.stop();
  }
}

class XmppOverQuicClientProtocol extends _XmppBase {
  XmppOverQuicClientProtocol(super.conn);

  @override
  Future<void> start() async {
    final s = await conn.openBidirectionalStream();
    print('🚀 [xmpp] opened stream id=${s.id}');
    _xmpp.complete(XmppOverQuicConnection._(s));
  }
}

class XmppOverQuicProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [xmppAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      XmppOverQuicServerProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      XmppOverQuicClientProtocol(conn);
}
