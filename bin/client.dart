// Modular QUIC client entry point.
//
// Demonstrates: UDP -> QUIC -> H3 (default) by ALPN selection.

import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()
    ..register(Http3ProtocolFactory())
    ..register(WebTransportProtocolFactory());

  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress('127.0.0.1'),
    remotePort: 4433,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'h3',
  );

  print('client dialing 127.0.0.1:4433 alpn=${ep.connection.alpn}');
  await ep.connection.ready;
  print('client handshake complete (peerCid=${ep.connection.peerCid})');

  // Subscribe to the WebTransport session that the H3 client module
  // opens automatically once it sees server SETTINGS, then send a test
  // datagram and verify the echo.
  final proto = ep.protocol;
  if (proto is Http3ClientProtocol) {
    proto.webTransportSessions.listen((wt) async {
      print('▶ wt session ready (client side): id=${wt.sessionId}');
      final probe = Uint8List.fromList([1, 2, 3, 4]);
      // Subscribe BEFORE sending so we don't miss the echo.
      wt.datagrams.listen((data) {
        final ok =
            data.length == probe.length &&
            List<int>.generate(data.length, (i) => data[i]).join(',') ==
                probe.join(',');
        print('▶ wt received echo len=${data.length} ok=$ok');
      });
      // Wait briefly for the server's CONNECT response before sending.
      await Future<void>.delayed(const Duration(milliseconds: 300));
      wt.sendDatagram(probe);
      print('▶ wt sent probe DATAGRAM ${probe.length} bytes');
    });
  }

  // Keep the client alive long enough for the round trip.
  await Future<void>.delayed(const Duration(seconds: 3));
  await ep.close();
}
