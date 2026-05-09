// End-to-end loopback test for Media-over-QUIC (MoQ-style).

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 30));

void main() {
  QuicServerEndpoint? server;
  late int port;
  var nextPort = 14730;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  test('subscribe + publish over DATAGRAM', () async {
    final alpns = AlpnRegistry()..register(MediaOverQuicProtocolFactory());
    server = await QuicServerEndpoint.bind(
      address: InternetAddress.loopbackIPv4,
      port: port,
      alpns: alpns,
    );

    server!.connections.listen((conn) {
      final proto = server!.protocolFor(conn);
      if (proto is MediaOverQuicServerProtocol) {
        proto.subscribes.listen((track) {
          for (var i = 0; i < 3; i++) {
            proto.publish(
              MoqObject(
                track: track,
                groupId: 0,
                objectId: i,
                payload: Uint8List.fromList('frame$i:$track'.codeUnits),
              ),
            );
          }
        });
      }
    });

    final clientAlpns = AlpnRegistry()
      ..register(MediaOverQuicProtocolFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: InternetAddress.loopbackIPv4,
      remotePort: port,
      authority: 'localhost',
      alpns: clientAlpns,
      alpn: 'moq-00',
    );
    addTearDown(ep.close);
    await ep.connection.ready;

    final proto = ep.protocol as MediaOverQuicClientProtocol;
    await proto.setupCompleted.timeout(const Duration(seconds: 10));

    final got = <MoqObject>[];
    final done = Completer<void>();
    proto.objects.listen((o) {
      got.add(o);
      if (got.length == 3) done.complete();
    });

    proto.subscribe('video/0');
    await done.future.timeout(const Duration(seconds: 10));

    expect(got, hasLength(3));
    for (var i = 0; i < 3; i++) {
      expect(got[i].objectId, i);
      expect(String.fromCharCodes(got[i].payload), 'frame$i:video/0');
    }
  }, timeout: _to);
}
