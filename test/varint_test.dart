// Round-trip tests for the QUIC variable-length integer codec
// in `lib/utils.dart`.

import 'dart:typed_data';

import 'package:pure_dart_quic/utils.dart';
import 'package:test/test.dart';

void _roundtrip(int value, int expectedLen) {
  final bytes = writeVarInt(value);
  expect(bytes.length, expectedLen, reason: 'encoding length for $value');
  final r = readVarInt(bytes, 0);
  expect(r, isNotNull, reason: 'decode failed for $value');
  expect(r!.value, value);
  expect(r.byteLength, bytes.length);
}

void main() {
  group('writeVarInt / readVarInt', () {
    test('1-byte boundary values', () {
      for (final v in [0, 1, 0x3e, 0x3f]) {
        _roundtrip(v, 1);
      }
    });

    test('2-byte boundary values', () {
      for (final v in [0x40, 0x41, 0x3ffe, 0x3fff]) {
        _roundtrip(v, 2);
      }
    });

    test('4-byte boundary values', () {
      for (final v in [0x4000, 0x10000, 0x3fffffff]) {
        _roundtrip(v, 4);
      }
    });

    test('8-byte boundary values', () {
      for (final v in [0x40000000, 0x100000000, 0x3fffffffffffffff]) {
        _roundtrip(v, 8);
      }
    });

    test('readVarInt returns null on truncated buffer', () {
      final full = writeVarInt(0x1234);
      final truncated = Uint8List.fromList(full.sublist(0, 1));
      expect(readVarInt(truncated, 0), isNull);
    });

    test('readVarInt honors offset', () {
      final a = writeVarInt(0x10); // 1 byte
      final b = writeVarInt(0x3242); // 2 bytes (< 0x4000)
      final concat = Uint8List.fromList(<int>[...a, ...b]);
      final r2 = readVarInt(concat, a.length);
      expect(r2, isNotNull);
      expect(r2!.value, 0x3242);
      expect(r2.byteLength, 2);
    });

    test('writeVarInt rejects values >= 2^62', () {
      expect(() => writeVarInt(0x4000000000000000), throwsException);
    });
  });
}
