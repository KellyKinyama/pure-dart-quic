// XMPP-over-QUIC example server.
//
// Listens on UDP 127.0.0.1:4435, accepts a single QUIC connection
// negotiated with ALPN `xmpp-quic`, then echoes every received
// stanza back wrapped in `<echo>...</echo>` and closes after a few
// seconds.

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(XmppOverQuicProtocolFactory());

  final endpoint = await QuicServerEndpoint.bind(
    address: InternetAddress('127.0.0.1'),
    port: 4435,
    alpns: alpns,
  );

  print(
    'xmpp server listening on ${endpoint.udp.address.address}:'
    '${endpoint.udp.port}  alpns=${alpns.advertisedAlpns}',
  );

  endpoint.connections.listen((conn) {
    print('accepted QUIC connection (alpn=${conn.alpn})');
    final proto = endpoint.protocolFor(conn);
    if (proto is XmppOverQuicServerProtocol) {
      proto.opened.then((xmpp) {
        print('▶ xmpp stream bound');
        xmpp.send(
          "<stream:features>"
          "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"
          "</stream:features>",
        );
        xmpp.stanzas.listen((s) {
          print('▶ xmpp recv: $s');
          xmpp.send('<echo>$s</echo>');
        });
      });
    }
  });
}
