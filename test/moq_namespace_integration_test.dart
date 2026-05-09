// End-to-end tests for the MoQ namespace / wildcard subscriptions, the
// MoqBroker stats counters, and the high-level MoqPublisher /
// MoqSubscriber convenience wrappers.

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

Future<void> _drain([int ms = 50]) =>
    Future<void>.delayed(Duration(milliseconds: ms));

void main() {
  QuicServerEndpoint? server;
  late int port;
  var nextPort = 14820;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await _drain(100);
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

  test(
    'prefix subscription receives objects from every matching track',
    () async {
      final broker = await startBroker();
      final sub = await _connect(port);
      final pub = await _connect(port);

      final received = <MoqObject>[];
      final got3 = Completer<void>();
      sub.objects.listen((o) {
        received.add(o);
        if (received.length >= 3 && !got3.isCompleted) got3.complete();
      });

      // Subscribe to anything under the "video/" namespace.
      sub.subscribe('video/*');
      await _drain(150);
      expect(broker.prefixSubscriptions, contains('video/*'));
      expect(broker.subscriberCount('video/cam-A'), 1);
      expect(broker.subscriberCount('video/cam-B'), 1);
      expect(broker.subscriberCount('audio/mix'), 0);

      // Publish on three different tracks, two of which match the prefix.
      pub.publish(
        MoqObject(
          track: 'video/cam-A',
          groupId: 0,
          objectId: 0,
          payload: Uint8List.fromList('A0'.codeUnits),
        ),
      );
      pub.publish(
        MoqObject(
          track: 'video/cam-B',
          groupId: 0,
          objectId: 0,
          payload: Uint8List.fromList('B0'.codeUnits),
        ),
      );
      pub.publish(
        MoqObject(
          track: 'audio/mix',
          groupId: 0,
          objectId: 0,
          payload: Uint8List.fromList('M0'.codeUnits),
        ),
      );
      pub.publish(
        MoqObject(
          track: 'video/cam-A',
          groupId: 0,
          objectId: 1,
          payload: Uint8List.fromList('A1'.codeUnits),
        ),
      );

      await got3.future.timeout(const Duration(seconds: 10));
      await _drain(100);

      final tracks = received.map((o) => o.track).toSet();
      expect(tracks, containsAll(<String>{'video/cam-A', 'video/cam-B'}));
      expect(tracks, isNot(contains('audio/mix')));
    },
    timeout: _to,
  );

  test('broker stats track published / delivered counts', () async {
    final broker = await startBroker();
    final sub1 = await _connect(port);
    final sub2 = await _connect(port);
    final pub = await _connect(port);

    final s1 = <MoqObject>[];
    final s2 = <MoqObject>[];
    sub1.objects.listen(s1.add);
    sub2.objects.listen(s2.add);
    sub1.subscribe('m/a');
    sub2.subscribe('m/a');
    await _drain(150);

    for (var i = 0; i < 4; i++) {
      pub.publish(
        MoqObject(track: 'm/a', groupId: 0, objectId: i, payload: Uint8List(8)),
      );
      await _drain(20);
    }

    // Drop on a track with no subscribers.
    pub.publish(
      MoqObject(
        track: 'm/none',
        groupId: 0,
        objectId: 0,
        payload: Uint8List(8),
      ),
    );

    await _drain(300);

    expect(broker.stats.published, 5);
    expect(broker.stats.publishedBytes, 40);
    // Each of 4 m/a publishes fans out to 2 subscribers.
    expect(broker.stats.delivered, 8);
    expect(broker.stats.deliveredBytes, 64);
    expect(broker.stats.deliveryErrors, 0);
    expect(s1.length, 4);
    expect(s2.length, 4);
  }, timeout: _to);

  test(
    'MoqPublisher auto-increments groupId/objectId, MoqSubscriber filters',
    () async {
      await startBroker();
      final subClient = await _connect(port);
      final pubClient = await _connect(port);

      final sub = await MoqSubscriber.subscribe(subClient, 'sensor/*');
      addTearDown(sub.close);

      final received = <MoqObject>[];
      final got4 = Completer<void>();
      sub.objects.listen((o) {
        received.add(o);
        if (received.length >= 4 && !got4.isCompleted) got4.complete();
      });

      await _drain(150);

      final p = MoqPublisher(pubClient, 'sensor/temp', groupSize: 3);
      p.send(Uint8List.fromList([1]));
      p.send(Uint8List.fromList([2]));
      p.send(Uint8List.fromList([3])); // triggers nextGroup() (groupSize=3)
      p.send(Uint8List.fromList([4]));

      // Publisher state: after 4 sends with groupSize=3 -> group 1, next obj 1.
      expect(p.groupId, 1);
      expect(p.nextObjectId, 1);

      await got4.future.timeout(const Duration(seconds: 10));

      expect(received[0].groupId, 0);
      expect(received[0].objectId, 0);
      expect(received[1].groupId, 0);
      expect(received[1].objectId, 1);
      expect(received[2].groupId, 0);
      expect(received[2].objectId, 2);
      expect(received[3].groupId, 1);
      expect(received[3].objectId, 0);

      // Every received object's track started with the prefix.
      for (final o in received) {
        expect(o.track, startsWith('sensor/'));
      }

      // Manual nextGroup() bumps the group id.
      p.nextGroup();
      expect(p.groupId, 2);
      expect(p.nextObjectId, 0);
    },
    timeout: _to,
  );
}
