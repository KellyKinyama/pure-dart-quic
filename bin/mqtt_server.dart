// MQTT-over-QUIC example server.
//
// Listens on UDP 127.0.0.1:4437, accepts a QUIC connection negotiated
// with ALPN `mqtt`, then responds to any CONNECT with a CONNACK and
// echoes PUBLISH packets back with topic `echo/<original>`.

import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(MqttOverQuicProtocolFactory());

  final endpoint = await QuicServerEndpoint.bind(
    address: InternetAddress('127.0.0.1'),
    port: 4437,
    alpns: alpns,
  );

  print(
    'mqtt server listening on ${endpoint.udp.address.address}:'
    '${endpoint.udp.port}  alpns=${alpns.advertisedAlpns}',
  );

  endpoint.connections.listen((conn) {
    print('accepted QUIC connection (alpn=${conn.alpn})');
    final proto = endpoint.protocolFor(conn);
    if (proto is MqttOverQuicServerProtocol) {
      proto.opened.then((mqtt) {
        print('▶ mqtt stream bound');
        mqtt.packets.listen((p) {
          print('▶ mqtt recv $p');
          if (p.type == MqttPacketType.connect) {
            // Minimal MQTT v3.1.1 CONNACK: session-present=0, code=0.
            mqtt.send(
              MqttPacket.simple(
                MqttPacketType.connack,
                Uint8List.fromList(const [0x00, 0x00]),
              ),
            );
          } else if (p.type == MqttPacketType.publish) {
            mqtt.send(p); // pure echo
          } else if (p.type == MqttPacketType.pingreq) {
            mqtt.send(MqttPacket.simple(MqttPacketType.pingresp, Uint8List(0)));
          }
        });
      });
    }
  });
}
