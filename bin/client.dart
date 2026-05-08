// Modular QUIC client entry point.
//
// Demonstrates: UDP -> QUIC -> H3 (default) by ALPN selection.
//
// Two flows on the same connection:
//   1. Plain HTTP/3 GETs (drives the request handler in
//      bin/http_server.dart).
//   2. WebTransport (auto-CONNECT + a probe DATAGRAM echo).
//
// To talk to the plain HTTP demo (bin/http_server.dart), run that
// server first; to talk to the WT echo demo, run bin/server.dart
// instead. The unsupported flow on the other side just stays idle.

import 'dart:async';
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

  final proto = ep.protocol;
  if (proto is Http3ClientProtocol) {
    // Match a WT route the demo server exposes (`/echo`).
    proto.wtPath = '/echo';
    // ----- 1) Plain HTTP/3 requests --------------------------------
    Future<void> fetch(String path) async {
      try {
        final resp = await proto.request('GET', path);
        final ct = resp.headers['content-type'] ?? '';
        print(
          '◀ HTTP/3 $path  status=${resp.status}  '
          'content-type=$ct  bodyLen=${resp.body.length}',
        );
        if (resp.body.isNotEmpty && resp.body.length < 512) {
          print('    body: ${resp.bodyAsString.trimRight()}');
        }
      } catch (e) {
        print('◀ HTTP/3 $path  ERROR: $e');
      }
    }

    // Don't await — let WT run in parallel with the HTTP traffic.
    unawaited(
      Future.wait<void>([
        fetch('/'),
        fetch('/hello'),
        fetch('/json'),
        fetch('/does-not-exist'),
      ]),
    );

    // ----- 2) WebTransport datagram echo --------------------------
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

  // Keep the client alive long enough for the round trips.
  await Future<void>.delayed(const Duration(seconds: 3));
  await ep.close();
}
