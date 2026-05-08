// End-to-end loopback test for XMPP-over-QUIC.

import 'dart:async';
import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 30));

void main() {
  QuicServerEndpoint? server;
  late int port;
  var nextPort = 14630;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  test('stanzas round-trip both directions', () async {
    final alpns = AlpnRegistry()..register(XmppOverQuicProtocolFactory());
    server = await QuicServerEndpoint.bind(
      address: InternetAddress.loopbackIPv4,
      port: port,
      alpns: alpns,
    );

    server!.connections.listen((_) async {
      final proto = server!.protocol;
      if (proto is XmppOverQuicServerProtocol) {
        final xmpp = await proto.opened;
        xmpp.stanzas.listen((s) => xmpp.send('<echo>$s</echo>'));
      }
    });

    final clientAlpns = AlpnRegistry()..register(XmppOverQuicProtocolFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: InternetAddress.loopbackIPv4,
      remotePort: port,
      authority: 'localhost',
      alpns: clientAlpns,
      alpn: 'xmpp-quic',
    );
    addTearDown(ep.close);
    await ep.connection.ready;

    final proto = ep.protocol as XmppOverQuicClientProtocol;
    final xmpp = await proto.opened.timeout(const Duration(seconds: 10));

    final replies = <String>[];
    final got = Completer<void>();
    xmpp.stanzas.listen((s) {
      replies.add(s);
      if (replies.length == 2) got.complete();
    });

    xmpp.send('<message>hi</message>');
    xmpp.send('<presence/>');

    await got.future.timeout(const Duration(seconds: 10));
    expect(replies, contains('<echo><message>hi</message></echo>'));
    expect(replies, contains('<echo><presence/></echo>'));
  }, timeout: _to);
}
