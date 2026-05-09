// End-to-end loopback tests for Media-over-QUIC fan-out via [MoqBroker].
//
// Topologies:
//   * one-to-many : 1 publisher -> 3 subscribers, single track.
//   * many-to-many: 3 publishers each on their own track, 3 subscribers
//                   each subscribed to all three tracks.

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

Future<void> _drain() => Future<void>.delayed(const Duration(milliseconds: 50));

void main() {
  QuicServerEndpoint? server;
  late int port;
  var nextPort = 14760;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  Future<MoqBroker> startBroker() async {
    final broker = MoqBroker();
    final alpns = AlpnRegistry()..register(MoqBrokerProtocolFactory(broker));
    server = await QuicServerEndpoint.bind(
      address: InternetAddress.loopbackIPv4,
      port: port,
      alpns: alpns,
    );
    return broker;
  }

  test('one-to-many: 1 publisher -> 3 subscribers (broker fan-out)', () async {
    final broker = await startBroker();

    // Connect 3 subscribers and 1 publisher.
    final subs = await Future.wait<MediaOverQuicClientProtocol>([
      _connect(port),
      _connect(port),
      _connect(port),
    ]);
    final pub = await _connect(port);

    // Each subscriber collects up to 5 objects on track 'video/cam-A'.
    const track = 'video/cam-A';
    const total = 5;
    final received = List<List<MoqObject>>.generate(subs.length, (_) => []);
    final dones = List<Completer<void>>.generate(
      subs.length,
      (_) => Completer<void>(),
    );
    for (var i = 0; i < subs.length; i++) {
      final idx = i;
      subs[idx].objects.listen((o) {
        if (o.track != track) return;
        received[idx].add(o);
        if (received[idx].length == total && !dones[idx].isCompleted) {
          dones[idx].complete();
        }
      });
      subs[idx].subscribe(track);
    }

    // Wait for the broker to register all 3 subscribers.
    await Future<void>.delayed(const Duration(milliseconds: 200));
    expect(broker.subscriberCount(track), 3);

    // Publish 5 frames from the publisher.
    for (var i = 0; i < total; i++) {
      pub.publish(
        MoqObject(
          track: track,
          groupId: 0,
          objectId: i,
          payload: Uint8List.fromList('frame-$i'.codeUnits),
        ),
      );
      await _drain();
    }

    await Future.wait(
      dones.map((d) => d.future),
    ).timeout(const Duration(seconds: 15));

    for (final r in received) {
      expect(r, hasLength(total));
      for (var i = 0; i < total; i++) {
        expect(r[i].objectId, i);
        expect(String.fromCharCodes(r[i].payload), 'frame-$i');
      }
    }

    // The publisher itself is not subscribed; broker should not have
    // echoed anything back to it. (It would still receive on its own
    // `objects` stream only if it had subscribed.)
    expect(broker.subscriberCount(track), 3);
  }, timeout: _to);

  test('many-to-many: 3 publishers x 3 subscribers across 3 tracks', () async {
    final broker = await startBroker();

    const tracks = ['cam-A', 'cam-B', 'cam-C'];
    const framesPerTrack = 4;

    // 3 publisher peers, each owning one track.
    final pubs = await Future.wait<MediaOverQuicClientProtocol>(
      List.generate(tracks.length, (_) => _connect(port)),
    );

    // 3 subscriber peers, each subscribed to all tracks.
    final subs = await Future.wait<MediaOverQuicClientProtocol>(
      List.generate(3, (_) => _connect(port)),
    );

    // Per-subscriber: track -> list of received objects.
    final got = List<Map<String, List<MoqObject>>>.generate(
      subs.length,
      (_) => {for (final t in tracks) t: <MoqObject>[]},
    );
    final dones = List<Completer<void>>.generate(
      subs.length,
      (_) => Completer<void>(),
    );

    void checkDone(int idx) {
      if (dones[idx].isCompleted) return;
      var sum = 0;
      for (final t in tracks) {
        sum += got[idx][t]!.length;
      }
      if (sum >= tracks.length * framesPerTrack) dones[idx].complete();
    }

    for (var i = 0; i < subs.length; i++) {
      final idx = i;
      subs[idx].objects.listen((o) {
        final list = got[idx][o.track];
        if (list == null) return;
        list.add(o);
        checkDone(idx);
      });
      for (final t in tracks) {
        subs[idx].subscribe(t);
      }
    }

    // Wait for the broker to register all subscriptions.
    await Future<void>.delayed(const Duration(milliseconds: 250));
    for (final t in tracks) {
      expect(broker.subscriberCount(t), 3, reason: 'track=$t');
    }

    // Each publisher emits framesPerTrack objects on its own track.
    for (var i = 0; i < tracks.length; i++) {
      final t = tracks[i];
      for (var j = 0; j < framesPerTrack; j++) {
        pubs[i].publish(
          MoqObject(
            track: t,
            groupId: 0,
            objectId: j,
            payload: Uint8List.fromList('$t#$j'.codeUnits),
          ),
        );
        await _drain();
      }
    }

    await Future.wait(
      dones.map((d) => d.future),
    ).timeout(const Duration(seconds: 20));

    // Every subscriber should have received exactly framesPerTrack
    // objects on every track, in order.
    for (var s = 0; s < subs.length; s++) {
      for (final t in tracks) {
        final list = got[s][t]!;
        expect(
          list,
          hasLength(framesPerTrack),
          reason: 'subscriber=$s track=$t',
        );
        for (var j = 0; j < framesPerTrack; j++) {
          expect(list[j].objectId, j);
          expect(String.fromCharCodes(list[j].payload), '$t#$j');
        }
      }
    }
  }, timeout: _to);

  test('unsubscribe stops further fan-out', () async {
    final broker = await startBroker();

    final sub = await _connect(port);
    final pub = await _connect(port);
    const track = 'metrics/cpu';

    final got = <MoqObject>[];
    sub.objects.listen((o) {
      if (o.track == track) got.add(o);
    });
    sub.subscribe(track);
    await Future<void>.delayed(const Duration(milliseconds: 150));
    expect(broker.subscriberCount(track), 1);

    pub.publish(
      MoqObject(
        track: track,
        groupId: 0,
        objectId: 0,
        payload: Uint8List.fromList([1]),
      ),
    );
    pub.publish(
      MoqObject(
        track: track,
        groupId: 0,
        objectId: 1,
        payload: Uint8List.fromList([2]),
      ),
    );

    // Wait for delivery.
    await Future<void>.delayed(const Duration(milliseconds: 200));
    expect(got, hasLength(2));

    sub.unsubscribe(track);
    await Future<void>.delayed(const Duration(milliseconds: 150));
    expect(broker.subscriberCount(track), 0);

    pub.publish(
      MoqObject(
        track: track,
        groupId: 0,
        objectId: 2,
        payload: Uint8List.fromList([3]),
      ),
    );
    await Future<void>.delayed(const Duration(milliseconds: 200));

    // Still only the original two.
    expect(got, hasLength(2));
  }, timeout: _to);
}
