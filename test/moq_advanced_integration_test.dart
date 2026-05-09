// Tests for Media-over-QUIC enhancements:
//   1. Reliable object delivery via unidirectional streams.
//   2. Broker catch-up cache replays recent objects to late subscribers.
//   3. Publisher ANNOUNCE is relayed by the broker to existing
//      subscribers.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 60));

Future<MediaOverQuicClientProtocol> _connect(int port) async {
  final alpns = AlpnRegistry()..register(MediaOverQuicProtocolFactory());
  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress.loopbackIPv4,
    remotePort: port,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'moq-00',
  );
  addTearDown(ep.close);
  await ep.connection.ready;
  final p = ep.protocol as MediaOverQuicClientProtocol;
  await p.setupCompleted.timeout(const Duration(seconds: 10));
  return p;
}

void main() {
  QuicServerEndpoint? server;
  late int port;
  var nextPort = 14790;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  Future<MoqBroker> startBroker({int cacheSize = 0}) async {
    final broker = MoqBroker(cacheSize: cacheSize);
    final alpns = AlpnRegistry()..register(MoqBrokerProtocolFactory(broker));
    server = await QuicServerEndpoint.bind(
      address: InternetAddress.loopbackIPv4,
      port: port,
      alpns: alpns,
    );
    return broker;
  }

  test('reliable stream delivery: 1 publisher -> 1 subscriber', () async {
    await startBroker();

    final sub = await _connect(port);
    final pub = await _connect(port);

    const track = 'video/keyframe';
    final got = <MoqObject>[];
    final done = Completer<void>();
    sub.objects.listen((o) {
      if (o.track != track) return;
      got.add(o);
      if (got.length == 3) done.complete();
    });
    sub.subscribe(track);
    await Future<void>.delayed(const Duration(milliseconds: 200));

    // Send a payload that's clearly larger than a typical DATAGRAM
    // (~1200 bytes MTU). Reliable streams have no MTU limit.
    final big = Uint8List(8 * 1024);
    for (var i = 0; i < big.length; i++) {
      big[i] = i & 0xff;
    }
    for (var i = 0; i < 3; i++) {
      await pub.publishReliable(
        MoqObject(track: track, groupId: 0, objectId: i, payload: big),
      );
    }

    await done.future.timeout(const Duration(seconds: 15));

    expect(got, hasLength(3));
    for (var i = 0; i < 3; i++) {
      expect(got[i].objectId, i);
      expect(got[i].payload.length, big.length);
      // Spot-check a few bytes.
      expect(got[i].payload[0], big[0]);
      expect(got[i].payload[1234], big[1234]);
      expect(got[i].payload[big.length - 1], big[big.length - 1]);
    }
  }, timeout: _to);

  test('broker cache replays recent objects to late subscribers', () async {
    final broker = await startBroker(cacheSize: 4);

    // Publisher connects first and emits 6 objects with no subscribers.
    final pub = await _connect(port);
    const track = 'metrics/cpu';

    for (var i = 0; i < 6; i++) {
      pub.publish(
        MoqObject(
          track: track,
          groupId: 0,
          objectId: i,
          payload: Uint8List.fromList([i]),
        ),
      );
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
    // Give the server time to ingest + cache.
    await Future<void>.delayed(const Duration(milliseconds: 200));

    // Late subscriber. Should receive the most recent 4 cached objects
    // (objectIds 2,3,4,5) via reliable streams when it subscribes.
    final sub = await _connect(port);
    final got = <MoqObject>[];
    final done = Completer<void>();
    sub.objects.listen((o) {
      if (o.track != track) return;
      got.add(o);
      if (got.length == 4) done.complete();
    });
    sub.subscribe(track);

    await done.future.timeout(const Duration(seconds: 15));

    expect(got, hasLength(4));
    final ids = got.map((o) => o.objectId).toList()..sort();
    expect(ids, [2, 3, 4, 5]);
    // Broker still has the same 4 objects cached.
    expect(broker.subscriberCount(track), 1);
  }, timeout: _to);

  test('ANNOUNCE from publisher is relayed to existing subscribers', () async {
    await startBroker();

    // Subscriber connects first, subscribes to *something* so the broker
    // tracks it as reachable.
    final sub = await _connect(port);
    sub.subscribe('placeholder');
    await Future<void>.delayed(const Duration(milliseconds: 150));

    final announces = <String>[];
    final got = Completer<void>();
    sub.announces.listen((t) {
      announces.add(t);
      if (t == 'live/cam-7' && !got.isCompleted) got.complete();
    });

    // Publisher connects and ANNOUNCEs a track.
    final pub = await _connect(port);
    pub.announce('live/cam-7');

    await got.future.timeout(const Duration(seconds: 10));
    expect(announces, contains('live/cam-7'));
  }, timeout: _to);
}
