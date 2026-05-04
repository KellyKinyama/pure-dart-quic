// Media-over-QUIC protocol module (STUB).
//
// Targets the IETF "Media over QUIC" (MoQ) family: low-latency media
// delivery using QUIC streams for reliable control + DATAGRAM frames
// for time-sensitive payloads (RTP-over-QUIC style).
//
// A real implementation would:
//   1. Open a control stream (SETUP / SUBSCRIBE messages).
//   2. Open per-track unidirectional streams for keyframes.
//   3. Send media samples over QUIC DATAGRAMs (RFC 9221).
// See draft-ietf-moq-transport.
//
// ALPN: `moq-00` (provisional).

import 'dart:async';

import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String moqAlpn = 'moq-00';

class MediaOverQuicServerProtocol implements ApplicationProtocol {
  @override
  final String alpn = moqAlpn;
  final QuicConnection conn;
  MediaOverQuicServerProtocol(this.conn);

  @override
  Future<void> start() async {
    // TODO: accept SETUP, route SUBSCRIBE, fan out via DATAGRAMs.
  }

  @override
  Future<void> stop() async {}
}

class MediaOverQuicClientProtocol implements ApplicationProtocol {
  @override
  final String alpn = moqAlpn;
  final QuicConnection conn;
  MediaOverQuicClientProtocol(this.conn);

  @override
  Future<void> start() async {
    // TODO: send SETUP, then SUBSCRIBE for tracks of interest.
  }

  @override
  Future<void> stop() async {}
}

class MediaOverQuicProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [moqAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      MediaOverQuicServerProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      MediaOverQuicClientProtocol(conn);
}
