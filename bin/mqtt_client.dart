// MQTT-over-QUIC example client.

import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(MqttOverQuicProtocolFactory());

  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress('127.0.0.1'),
    remotePort: 4437,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'mqtt',
  );

  print('mqtt client dialing 127.0.0.1:4437 alpn=${ep.connection.alpn}');
  await ep.connection.ready;
  print('mqtt client handshake complete');

  final proto = ep.protocol;
  if (proto is MqttOverQuicClientProtocol) {
    final mqtt = await proto.opened;
    print('▶ mqtt stream open id=${mqtt.stream.id}');

    mqtt.packets.listen((p) => print('▶ mqtt recv $p'));

    // CONNECT (MQTT v3.1.1, minimal): protocol "MQTT", level 4, clean
    // session, keep-alive 60s, client id "demo".
    final connect = BytesBuilder()
      ..add([0x00, 0x04, 0x4d, 0x51, 0x54, 0x54]) // "MQTT"
      ..addByte(0x04) // protocol level (3.1.1)
      ..addByte(0x02) // clean session
      ..add([0x00, 0x3c]) // keep-alive 60
      ..add([0x00, 0x04, 0x64, 0x65, 0x6d, 0x6f]); // client id "demo"
    mqtt.send(MqttPacket.simple(MqttPacketType.connect, connect.toBytes()));

    // PUBLISH topic "hello/quic" payload "world".
    final publish = BytesBuilder()
      ..add([0x00, 0x0a]) // topic length
      ..add('hello/quic'.codeUnits)
      ..add('world'.codeUnits);
    mqtt.send(
      MqttPacket(
        MqttPacketType.publish,
        0, // QoS 0, no DUP, no RETAIN
        Uint8List.fromList(publish.toBytes()),
      ),
    );
    print('▶ mqtt sent CONNECT + PUBLISH');
  }

  await Future<void>.delayed(const Duration(seconds: 3));
  await ep.close();
}
