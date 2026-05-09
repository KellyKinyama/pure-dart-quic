// Media-over-QUIC (MoQ-style) example server.
//
// Listens on UDP 127.0.0.1:4436. After SETUP+SUBSCRIBE, publishes a
// stream of synthetic media objects via QUIC DATAGRAMs at ~10 fps.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(MediaOverQuicProtocolFactory());

  final endpoint = await QuicServerEndpoint.bind(
    address: InternetAddress('127.0.0.1'),
    port: 4436,
    alpns: alpns,
  );

  print(
    'moq server listening on ${endpoint.udp.address.address}:'
    '${endpoint.udp.port}  alpns=${alpns.advertisedAlpns}',
  );

  endpoint.connections.listen((conn) {
    print('accepted QUIC connection (alpn=${conn.alpn})');
    final proto = endpoint.protocolFor(conn);
    if (proto is MediaOverQuicServerProtocol) {
      proto.subscribes.listen((track) {
        print('▶ moq subscriber wants track=$track — starting publisher');
        var groupId = 0;
        var objectId = 0;
        Timer.periodic(const Duration(milliseconds: 100), (t) {
          final payload = Uint8List.fromList(
            'frame g=$groupId o=$objectId track=$track'.codeUnits,
          );
          proto.publish(
            MoqObject(
              track: track,
              groupId: groupId,
              objectId: objectId,
              payload: payload,
            ),
          );
          objectId++;
          if (objectId >= 5) {
            objectId = 0;
            groupId++;
          }
          if (groupId >= 4) t.cancel();
        });
      });
    }
  });
}
