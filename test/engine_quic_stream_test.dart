// Unit tests for [EngineQuicStream] — the per-stream reassembly /
// write adapter that bridges the modular API to the engine.

import 'dart:async';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

class _Send {
  final List<({int sid, Uint8List data, bool fin, int offset})> calls = [];
  void call(int sid, Uint8List data, {bool fin = false, int offset = 0}) {
    calls.add((sid: sid, data: data, fin: fin, offset: offset));
  }
}

void main() {
  group('EngineQuicStream — inbound reassembly', () {
    test('in-order chunks emit immediately', () async {
      final s = EngineQuicStream(id: 0, send: _Send().call);
      final got = <Uint8List>[];
      final done = Completer<void>();
      s.incoming.listen(got.add, onDone: done.complete);

      s.deliverIncoming(0, Uint8List.fromList([1, 2, 3]), false);
      s.deliverIncoming(3, Uint8List.fromList([4, 5]), true);

      await done.future;
      expect(got.expand((x) => x).toList(), [1, 2, 3, 4, 5]);
    });

    test('out-of-order chunks are reassembled', () async {
      final s = EngineQuicStream(id: 0, send: _Send().call);
      final got = <int>[];
      final done = Completer<void>();
      s.incoming.listen(got.addAll, onDone: done.complete);

      s.deliverIncoming(3, Uint8List.fromList([4, 5, 6]), false);
      s.deliverIncoming(0, Uint8List.fromList([1, 2, 3]), false);
      s.deliverIncoming(6, Uint8List.fromList([7, 8]), true);

      await done.future;
      expect(got, [1, 2, 3, 4, 5, 6, 7, 8]);
    });

    test('overlapping chunk is trimmed', () async {
      final s = EngineQuicStream(id: 0, send: _Send().call);
      final got = <int>[];
      final done = Completer<void>();
      s.incoming.listen(got.addAll, onDone: done.complete);

      s.deliverIncoming(0, Uint8List.fromList([1, 2, 3, 4]), false);
      // Overlaps last byte of previous chunk; only [5,6] should be added.
      s.deliverIncoming(3, Uint8List.fromList([4, 5, 6]), true);

      await done.future;
      expect(got, [1, 2, 3, 4, 5, 6]);
    });

    test('FIN before all gaps filled defers stream close', () async {
      final s = EngineQuicStream(id: 0, send: _Send().call);
      final got = <int>[];
      var closed = false;
      s.incoming.listen(got.addAll, onDone: () => closed = true);

      // Gap: deliver [3..6) with FIN before [0..3).
      s.deliverIncoming(3, Uint8List.fromList([4, 5, 6]), true);
      await Future<void>.delayed(Duration.zero);
      expect(closed, isFalse, reason: 'must not close until gap filled');

      s.deliverIncoming(0, Uint8List.fromList([1, 2, 3]), false);
      await Future<void>.delayed(Duration.zero);

      expect(got, [1, 2, 3, 4, 5, 6]);
      expect(closed, isTrue);
    });

    test('inbound buffered until consumer subscribes', () async {
      final s = EngineQuicStream(id: 0, send: _Send().call);
      s.deliverIncoming(0, Uint8List.fromList([10, 20]), true);

      final got = <int>[];
      await s.incoming.forEach(got.addAll);
      expect(got, [10, 20]);
    });
  });

  group('EngineQuicStream — outbound', () {
    test('write tracks offset and FIN', () {
      final send = _Send();
      final s = EngineQuicStream(id: 4, send: send.call);

      s.write(Uint8List.fromList([1, 2, 3]));
      s.write(Uint8List.fromList([4, 5]), fin: true);

      expect(send.calls, hasLength(2));
      expect(send.calls[0].offset, 0);
      expect(send.calls[0].fin, isFalse);
      expect(send.calls[1].offset, 3);
      expect(send.calls[1].fin, isTrue);
    });

    test('write after local FIN throws', () {
      final s = EngineQuicStream(id: 4, send: _Send().call);
      s.write(Uint8List.fromList([1]), fin: true);
      expect(
        () => s.write(Uint8List.fromList([2])),
        throwsA(isA<StateError>()),
      );
    });

    test('write to a non-writable stream throws', () {
      final s = EngineQuicStream(id: 4, send: _Send().call, writable: false);
      expect(
        () => s.write(Uint8List.fromList([1])),
        throwsA(isA<StateError>()),
      );
    });
  });
}
