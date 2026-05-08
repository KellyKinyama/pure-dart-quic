// XMPP-over-QUIC example client.

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(XmppOverQuicProtocolFactory());

  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress('127.0.0.1'),
    remotePort: 4435,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'xmpp-quic',
  );

  print('xmpp client dialing 127.0.0.1:4435 alpn=${ep.connection.alpn}');
  await ep.connection.ready;
  print('xmpp client handshake complete');

  final proto = ep.protocol;
  if (proto is XmppOverQuicClientProtocol) {
    final xmpp = await proto.opened;
    print('▶ xmpp stream open id=${xmpp.stream.id}');

    xmpp.stanzas.listen((s) => print('▶ xmpp recv: $s'));

    // Send <stream:stream> and a <message> stanza.
    xmpp.send(
      "<stream:stream to='localhost' xmlns='jabber:client' "
      "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'/>",
    );
    xmpp.send(
      "<message to='alice@localhost' from='bob@localhost' type='chat'>"
      "<body>hello over QUIC</body>"
      "</message>",
    );
    print('▶ xmpp sent stream open + message');
  }

  await Future<void>.delayed(const Duration(seconds: 3));
  await ep.close();
}
