// Pure unit tests for `splitCoalescedPackets` in lib/constants.dart.

import 'dart:typed_data';

import 'package:pure_dart_quic/constants.dart';
import 'package:pure_dart_quic/utils.dart';
import 'package:test/test.dart';

/// Build a minimal QUIC long-header packet (Initial type) with an
/// empty token and the given payload bytes. This is just enough for
/// `splitCoalescedPackets` to walk the header — the payload is not
/// decryptable.
Uint8List _initial({
  required List<int> dcid,
  required List<int> scid,
  required Uint8List payload,
}) {
  final b = BytesBuilder();
  b.addByte(0xc0); // long-header, Initial, fixed bit
  b.add([0x00, 0x00, 0x00, 0x01]); // version 1
  b.addByte(dcid.length);
  b.add(dcid);
  b.addByte(scid.length);
  b.add(scid);
  b.add(writeVarInt(0)); // token length 0
  b.add(writeVarInt(payload.length)); // payload length
  b.add(payload);
  return b.toBytes();
}

Uint8List _short(Uint8List body) {
  final b = BytesBuilder();
  b.addByte(0x40); // short header, fixed bit
  b.add(body);
  return b.toBytes();
}

void main() {
  group('splitCoalescedPackets', () {
    test('returns empty for empty buffer', () {
      expect(splitCoalescedPackets(Uint8List(0)), isEmpty);
    });

    test('passes through a single long-header packet', () {
      final pkt = _initial(
        dcid: [1, 2, 3, 4],
        scid: [5, 6, 7, 8],
        payload: Uint8List.fromList(List<int>.filled(20, 0x42)),
      );
      final out = splitCoalescedPackets(pkt);
      expect(out, hasLength(1));
      expect(out.first, orderedEquals(pkt));
    });

    test('splits two coalesced long-header packets', () {
      final a = _initial(
        dcid: [1, 2, 3, 4],
        scid: [5, 6, 7, 8],
        payload: Uint8List.fromList(List<int>.filled(20, 0x11)),
      );
      final b = _initial(
        dcid: [9, 10, 11, 12],
        scid: [13, 14, 15, 16],
        payload: Uint8List.fromList(List<int>.filled(40, 0x22)),
      );
      final coalesced = Uint8List.fromList(<int>[...a, ...b]);
      final out = splitCoalescedPackets(coalesced);
      expect(out, hasLength(2));
      expect(out[0], orderedEquals(a));
      expect(out[1], orderedEquals(b));
    });

    test('long packet followed by short packet (short consumes rest)', () {
      final long = _initial(
        dcid: [1, 2, 3, 4],
        scid: [5, 6, 7, 8],
        payload: Uint8List.fromList(List<int>.filled(20, 0x33)),
      );
      final short = _short(Uint8List.fromList(List<int>.filled(15, 0x99)));
      final coalesced = Uint8List.fromList(<int>[...long, ...short]);
      final out = splitCoalescedPackets(coalesced);
      expect(out.length, greaterThanOrEqualTo(1));
      // First emitted packet must be the long one byte-for-byte.
      expect(out.first, orderedEquals(long));
    });
  });
}
