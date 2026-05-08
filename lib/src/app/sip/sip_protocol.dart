// SIP-over-QUIC protocol module (STUB).
//
// SIP messages can ride QUIC streams (reliable, ordered) instead of
// TCP/TLS or UDP. Each SIP transaction maps to a unidirectional
// stream pair, or all SIP traffic muxes onto a single bidi control
// stream. See draft-hurst-sip-quic for design alternatives.
//
// ALPN: `sip` (provisional).

import 'dart:async';

import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String sipAlpn = 'sip';

class SipOverQuicServerProtocol implements ApplicationProtocol {
  @override
  final String alpn = sipAlpn;
  final QuicConnection conn;
  SipOverQuicServerProtocol(this.conn);

  @override
  Future<void> start() async {
    // TODO: accept SIP requests on incoming streams.
  }

  @override
  Future<void> stop() async {}
}

class SipOverQuicClientProtocol implements ApplicationProtocol {
  @override
  final String alpn = sipAlpn;
  final QuicConnection conn;
  SipOverQuicClientProtocol(this.conn);

  @override
  Future<void> start() async {
    // TODO: send REGISTER / INVITE on a fresh stream.
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
