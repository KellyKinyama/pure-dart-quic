// Modular QUIC server entry point.
//
// Demonstrates: UDP -> QUIC -> {HTTP/3, WebTransport} via ALPN.
// To enable XMPP / Media / SIP over QUIC, register their factories
// alongside (each factory contributes its own ALPN identifiers).

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()
    ..register(Http3ProtocolFactory())
    ..register(WebTransportProtocolFactory())
  // Stubs — uncomment to advertise:
  // ..register(XmppOverQuicProtocolFactory())
  // ..register(MediaOverQuicProtocolFactory())
  // ..register(SipOverQuicProtocolFactory())
  ;

  final endpoint = await QuicServerEndpoint.bind(
    address: InternetAddress('127.0.0.1'),
    port: 4433,
    alpns: alpns,
  );

  print(
    'modular server listening on ${endpoint.udp.address.address}:'
    '${endpoint.udp.port}  alpns=${alpns.advertisedAlpns}',
  );

  endpoint.connections.listen((conn) {
    print('accepted QUIC connection (alpn=${conn.alpn})');
    // Subscribe immediately so we don't race the H3 module's first
    // session-add against this listener registration.
    final proto = endpoint.protocol;
    if (proto is Http3ServerProtocol) {
      proto.webTransportSessions.listen((wt) {
        print('▶ wt session opened: id=${wt.sessionId}');
        wt.datagrams.listen((data) {
          print('▶ wt echo session=${wt.sessionId} len=${data.length}');
          wt.sendDatagram(data);
        });
      });
    }
    conn.ready.then((_) => print('handshake complete'));
  });
}
