// XMPP-over-QUIC protocol module (STUB).
//
// This is a registration-only skeleton. A real implementation would:
//   1. Open a single bidirectional QUIC stream as the XMPP "stream".
//   2. Exchange `<stream:stream>` opening tags + STARTTLS-equivalent
//      setup (already done by QUIC handshake — XMPP can skip TLS).
//   3. Frame XMPP stanzas (XML, length-prefixed or whitespace-delimited)
//      over that stream.
// See draft-moffitt-xmpp-over-quic for design notes.
//
// ALPN: `xmpp-quic` (provisional).

import 'dart:async';

import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String xmppAlpn = 'xmpp-quic';

class XmppOverQuicServerProtocol implements ApplicationProtocol {
  @override
  final String alpn = xmppAlpn;
  final QuicConnection conn;
  XmppOverQuicServerProtocol(this.conn);

  @override
  Future<void> start() async {
    // TODO: accept incoming bidi stream, parse XMPP stanzas.
  }

  @override
  Future<void> stop() async {}
}

class XmppOverQuicClientProtocol implements ApplicationProtocol {
  @override
  final String alpn = xmppAlpn;
  final QuicConnection conn;
  XmppOverQuicClientProtocol(this.conn);

  @override
  Future<void> start() async {
    // TODO: open bidi stream, send `<stream:stream>` open tag.
  }

  @override
  Future<void> stop() async {}
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
