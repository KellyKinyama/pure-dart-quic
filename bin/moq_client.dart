// Media-over-QUIC (MoQ-style) example client.

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(MediaOverQuicProtocolFactory());

  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress('127.0.0.1'),
    remotePort: 4436,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'moq-00',
  );

  print('moq client dialing 127.0.0.1:4436 alpn=${ep.connection.alpn}');
  await ep.connection.ready;
  print('moq client handshake complete');

  final proto = ep.protocol;
  if (proto is MediaOverQuicClientProtocol) {
    await proto.setupCompleted;
    print('▶ moq SETUP complete; subscribing to track=video/0');
    proto.subscribe('video/0');

    proto.objects.listen((obj) {
      print('▶ moq received $obj');
    });
  }

  await Future<void>.delayed(const Duration(seconds: 5));
  await ep.close();
}
