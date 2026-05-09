// End-to-end loopback test for Redis-over-QUIC (RESP framing).

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 30));

void main() {
  QuicServerEndpoint? server;
  late int port;
  var nextPort = 15330;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  test('PING → +PONG and SET/GET behave like a tiny in-memory store', () async {
    final alpns = AlpnRegistry()..register(RedisOverQuicProtocolFactory());
    server = await QuicServerEndpoint.bind(
      address: InternetAddress.loopbackIPv4,
      port: port,
      alpns: alpns,
    );

    final store = <String, Uint8List>{};

    server!.connections.listen((conn) async {
      final proto = server!.protocolFor(conn);
      if (proto is RedisOverQuicServerProtocol) {
        final redis = await proto.opened;
        redis.values.listen((v) {
          // Expect command arrays of bulk strings.
          if (v.kind != 0x2a || v.value == null) return;
          final items = (v.value as List<RedisValue>);
          final argv = items
              .map<String>((e) => utf8.decode(e.value as Uint8List))
              .toList();
          switch (argv[0].toUpperCase()) {
            case 'PING':
              redis.send(RedisValue.simpleString('PONG'));
              break;
            case 'SET':
              store[argv[1]] = Uint8List.fromList(utf8.encode(argv[2]));
              redis.send(RedisValue.simpleString('OK'));
              break;
            case 'GET':
              final v = store[argv[1]];
              redis.send(
                v == null ? RedisValue.nullBulk() : RedisValue.bulkString(v),
              );
              break;
            default:
              redis.send(RedisValue.error('ERR unknown command'));
          }
        });
      }
    });

    final clientAlpns = AlpnRegistry()
      ..register(RedisOverQuicProtocolFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: InternetAddress.loopbackIPv4,
      remotePort: port,
      authority: 'localhost',
      alpns: clientAlpns,
      alpn: 'redis',
    );
    addTearDown(ep.close);
    await ep.connection.ready;

    final proto = ep.protocol as RedisOverQuicClientProtocol;
    final redis = await proto.opened.timeout(const Duration(seconds: 10));

    final replies = <RedisValue>[];
    final got = Completer<void>();
    redis.values.listen((v) {
      replies.add(v);
      if (replies.length == 3) got.complete();
    });

    redis.command(['PING']);
    redis.command(['SET', 'greeting', 'hello-quic']);
    redis.command(['GET', 'greeting']);

    await got.future.timeout(const Duration(seconds: 10));
    expect(replies[0].kind, 0x2b);
    expect(replies[0].value, 'PONG');
    expect(replies[1].kind, 0x2b);
    expect(replies[1].value, 'OK');
    expect(replies[2].kind, 0x24);
    expect(utf8.decode(replies[2].value as Uint8List), 'hello-quic');
  }, timeout: _to);
}
