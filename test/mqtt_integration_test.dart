// End-to-end loopback test for MQTT-over-QUIC.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 30));

void main() {
  QuicServerEndpoint? server;
  late int port;
  var nextPort = 15130;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  test('control packets round-trip both directions', () async {
    final alpns = AlpnRegistry()..register(MqttOverQuicProtocolFactory());
    server = await QuicServerEndpoint.bind(
      address: InternetAddress.loopbackIPv4,
      port: port,
      alpns: alpns,
    );

    server!.connections.listen((conn) async {
      final proto = server!.protocolFor(conn);
      if (proto is MqttOverQuicServerProtocol) {
        final mqtt = await proto.opened;
        mqtt.packets.listen((p) {
          if (p.type == MqttPacketType.connect) {
            mqtt.send(
              MqttPacket.simple(
                MqttPacketType.connack,
                Uint8List.fromList(const [0x00, 0x00]),
              ),
            );
          } else if (p.type == MqttPacketType.publish) {
            mqtt.send(p);
          }
        });
      }
    });

    final clientAlpns = AlpnRegistry()..register(MqttOverQuicProtocolFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: InternetAddress.loopbackIPv4,
      remotePort: port,
      authority: 'localhost',
      alpns: clientAlpns,
      alpn: 'mqtt',
    );
    addTearDown(ep.close);
    await ep.connection.ready;

    final proto = ep.protocol as MqttOverQuicClientProtocol;
    final mqtt = await proto.opened.timeout(const Duration(seconds: 10));

    final received = <MqttPacket>[];
    final got = Completer<void>();
    mqtt.packets.listen((p) {
      received.add(p);
      if (received.length == 2) got.complete();
    });

    mqtt.send(
      MqttPacket.simple(
        MqttPacketType.connect,
        Uint8List.fromList(const [
          0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, // "MQTT"
          0x04, 0x02, 0x00, 0x3c, // level, flags, keepalive
          0x00, 0x04, 0x64, 0x65, 0x6d, 0x6f, // client id "demo"
        ]),
      ),
    );

    final publishBody = Uint8List.fromList([
      0x00, 0x05, // topic len
      ...'topic'.codeUnits,
      ...'payload'.codeUnits,
    ]);
    mqtt.send(MqttPacket(MqttPacketType.publish, 0, publishBody));

    await got.future.timeout(const Duration(seconds: 10));
    expect(received[0].type, MqttPacketType.connack);
    expect(received[0].body, equals(Uint8List.fromList(const [0x00, 0x00])));
    expect(received[1].type, MqttPacketType.publish);
    expect(received[1].body, equals(publishBody));
  }, timeout: _to);

  test(
    'large packets fragment and reassemble across the bidi stream',
    () async {
      final alpns = AlpnRegistry()..register(MqttOverQuicProtocolFactory());
      server = await QuicServerEndpoint.bind(
        address: InternetAddress.loopbackIPv4,
        port: port,
        alpns: alpns,
      );

      server!.connections.listen((conn) async {
        final proto = server!.protocolFor(conn);
        if (proto is MqttOverQuicServerProtocol) {
          final mqtt = await proto.opened;
          mqtt.packets.listen(mqtt.send);
        }
      });

      final clientAlpns = AlpnRegistry()
        ..register(MqttOverQuicProtocolFactory());
      final ep = await QuicClientEndpoint.connect(
        remoteAddress: InternetAddress.loopbackIPv4,
        remotePort: port,
        authority: 'localhost',
        alpns: clientAlpns,
        alpn: 'mqtt',
      );
      addTearDown(ep.close);
      await ep.connection.ready;

      final proto = ep.protocol as MqttOverQuicClientProtocol;
      final mqtt = await proto.opened.timeout(const Duration(seconds: 10));

      // 5 KiB body — exercises 2-byte VarInt remaining-length encoding.
      final body = Uint8List(5000);
      for (var i = 0; i < body.length; i++) {
        body[i] = i & 0xff;
      }
      final got = Completer<MqttPacket>();
      mqtt.packets.listen(got.complete);
      mqtt.send(MqttPacket(MqttPacketType.publish, 0, body));

      final reply = await got.future.timeout(const Duration(seconds: 10));
      expect(reply.type, MqttPacketType.publish);
      expect(reply.body.length, body.length);
      expect(reply.body, equals(body));
    },
    timeout: _to,
  );
}
