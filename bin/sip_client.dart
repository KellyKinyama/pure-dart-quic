// SIP-over-QUIC demo client. Sends a REGISTER and prints the response.

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(SipOverQuicProtocolFactory());

  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress('127.0.0.1'),
    remotePort: 4440,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'sip',
  );
  await ep.connection.ready;

  final proto = ep.protocol as SipOverQuicClientProtocol;
  await proto.ready;

  final reg = SipMessage.request(
    method: 'REGISTER',
    requestUri: 'sip:localhost',
    headers: const [
      MapEntry('Via', 'SIP/2.0/QUIC localhost;branch=z9hG4bK-demo-1'),
      MapEntry('Max-Forwards', '70'),
      MapEntry('From', '<sip:alice@localhost>;tag=alice-1'),
      MapEntry('To', '<sip:alice@localhost>'),
      MapEntry('Call-ID', 'demo-call-1@localhost'),
      MapEntry('CSeq', '1 REGISTER'),
      MapEntry('Contact', '<sip:alice@127.0.0.1:4440;transport=quic>'),
      MapEntry('User-Agent', 'pure-dart-quic-sip/0.1'),
    ],
  );

  final responses = await proto.send(reg);
  await for (final r in responses) {
    print('◀ sip $r');
    if ((r.statusCode ?? 0) >= 200) break;
  }

  await ep.close();
}
