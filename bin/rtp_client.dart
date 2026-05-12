// RTP-over-QUIC (RoQ) example client.

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(RtpOverQuicProtocolFactory());

  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress('127.0.0.1'),
    remotePort: 4439,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'roq-09',
  );

  print('roq client dialing 127.0.0.1:4439 alpn=${ep.connection.alpn}');
  await ep.connection.ready;
  print('roq client handshake complete');

  final proto = ep.protocol;
  if (proto is RtpOverQuicProtocol) {
    var datagrams = 0;
    var streamed = 0;
    proto.incoming.listen((p) {
      if (p.transport == RtpTransport.datagram) {
        datagrams++;
      } else {
        streamed++;
      }
      print('▶ roq client received $p');
    });
    await Future<void>.delayed(const Duration(seconds: 3));
    print('roq client summary: datagrams=$datagrams stream_packets=$streamed');
  }

  await ep.close();
}
