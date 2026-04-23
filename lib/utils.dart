import 'dart:typed_data';
import 'dart:math';

typedef ConnectionID = Uint8List;

class Number {
  static final MAX_SAFE_INTEGER = pow(9007199254740991, 53) - 1;
}

// Uint8List writeVarInt(value) {
//   if (value < 0x40) {
//     // 1 byte, prefix 00
//     return Uint8List.fromList([value]); // אין צורך ב־& 0x3f
//   }

//   if (value < 0x4000) {
//     // 2 bytes, prefix 01
//     return Uint8List.fromList([0x40 | (value >> 8), value & 0xff]);
//   }

//   if (value < 0x40000000) {
//     // 4 bytes, prefix 10
//     return Uint8List.fromList([
//       0x80 | (value >> 24),
//       (value >> 16) & 0xff,
//       (value >> 8) & 0xff,
//       value & 0xff,
//     ]);
//   }

//   if (value <= Number.MAX_SAFE_INTEGER) {
//     final hi = pow(value / 2, 32).toInt(); // Math.floor(value / 2 ** 32);
//     final lo = value >> 0;
//     return Uint8List.fromList([
//       0xC0 | (hi >> 24),
//       (hi >> 16) & 0xff,
//       (hi >> 8) & 0xff,
//       hi & 0xff,
//       (lo >> 24) & 0xff,
//       (lo >> 16) & 0xff,
//       (lo >> 8) & 0xff,
//       lo & 0xff,
//     ]);
//   }

//   throw Exception("Value too large for QUIC VarInt");
// }

Uint8List writeVarInt2(value) {
  if (value < 0x40) {
    // 1 byte
    return Uint8List.fromList([value & 0x3f]);
  }

  if (value < 0x4000) {
    // 2 bytes
    return Uint8List.fromList([0x40 | ((value >> 8) & 0x3f), value & 0xff]);
  }

  if (value < 0x40000000) {
    // 4 bytes
    return Uint8List.fromList([
      0x80 | ((value >> 24) & 0x3f),
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff,
    ]);
  }

  if (value <= Number.MAX_SAFE_INTEGER) {
    final hi = pow(value / 2, 32).toInt(); // Math.floor(value / 2 ** 32);

    var lo = value >> 0;
    return Uint8List.fromList([
      0xC0 | ((hi >> 24) & 0x3f),
      (hi >> 16) & 0xff,
      (hi >> 8) & 0xff,
      hi & 0xff,
      (lo >> 24) & 0xff,
      (lo >> 16) & 0xff,
      (lo >> 8) & 0xff,
      lo & 0xff,
    ]);
  }

  throw Exception("Value too large for QUIC VarInt");
}

// Dart equivalent for writeVarInt
Uint8List writeVarInt(int value) {
  if (value < 0x40) {
    // 1 byte (00 prefix)
    return Uint8List.fromList([value]);
  }
  if (value < 0x4000) {
    // 2 bytes (01 prefix)
    return Uint8List.fromList([0x40 | (value >> 8) & 0x3F, value & 0xFF]);
  }
  if (value < 0x40000000) {
    // 4 bytes (10 prefix)
    // Dart integers are 64-bit, so this is safe.
    return Uint8List.fromList([
      0x80 | (value >> 24) & 0x3F,
      (value >> 16) & 0xFF,
      (value >> 8) & 0xFF,
      value & 0xFF,
    ]);
  }

  // For 8-byte (11 prefix), you must handle the full 62 bits:
  if (value < 0x4000000000000000) {
    // Use ByteData to ensure correct 64-bit little-endian writing.
    final buffer = ByteData(8);
    buffer.setUint64(0, value, Endian.big); // Write 64-bit value

    // Dart integers up to 2^63 - 1 are safe.
    return Uint8List.fromList([
      0xC0 | (buffer.getUint8(0) & 0x3F),
      buffer.getUint8(1),
      buffer.getUint8(2),
      buffer.getUint8(3),
      buffer.getUint8(4),
      buffer.getUint8(5),
      buffer.getUint8(6),
      buffer.getUint8(7),
    ]);
  }
  throw Exception("Value too large for QUIC VarInt");
}

/// Represents the result of reading a Variable-Length Integer (VarInt).
class VarIntReadResult {
  final int value;
  final int byteLength;
  const VarIntReadResult({required this.value, required this.byteLength});
}

/// Reads a QUIC Variable-Length Integer from a byte array starting at a given offset.
///
/// Returns a [VarIntReadResult] containing the decoded value and its byte length,
/// or `null` if the buffer is too short.
VarIntReadResult? readVarInt(Uint8List array, int offset) {
  if (offset >= array.length) return null;

  final first = array[offset];
  final prefix = first >> 6;

  // 1-byte encoding (00xxxxxx)
  if (prefix == 0) {
    return VarIntReadResult(
      value: first & 0x3f, // Mask the two prefix bits
      byteLength: 1,
    );
  }

  // 2-byte encoding (01xxxxxx)
  if (prefix == 0x01) {
    if (offset + 1 >= array.length) return null;

    // value = (01xxxxxx & 0x3f) << 8 | array[offset + 1]
    final value = ((first & 0x3f) << 8) | array[offset + 1];
    return VarIntReadResult(value: value, byteLength: 2);
  }

  // 4-byte encoding (10xxxxxx)
  if (prefix == 0x02) {
    if (offset + 3 >= array.length) return null;

    final value =
        ((first & 0x3F) << 24) |
        (array[offset + 1] << 16) |
        (array[offset + 2] << 8) |
        array[offset + 3];

    // Dart's `int` is 64-bit and handles the result directly.
    return VarIntReadResult(value: value, byteLength: 4);
  }

  // 8-byte encoding (11xxxxxx)
  if (prefix == 0x03) {
    if (offset + 7 >= array.length) return null;

    // In Dart, we can construct the full 62-bit value directly into a 64-bit `int`.
    // value = (11xxxxxx & 0x3F) << 56 | B1 << 48 | ... | B7
    int value = (first & 0x3F) << 56;
    value |= array[offset + 1] << 48;
    value |= array[offset + 2] << 40;
    value |= array[offset + 3] << 32;
    value |= array[offset + 4] << 24;
    value |= array[offset + 5] << 16;
    value |= array[offset + 6] << 8;
    value |= array[offset + 7];

    return VarIntReadResult(value: value, byteLength: 8);
  }

  // Should be unreachable given the 2-bit prefix logic, but included for completeness
  return null;
}

Uint8List concatUint8Lists(List<Uint8List> arrays) {
  // Efficiently combine all lists
  final buffer = BytesBuilder(copy: false);
  for (var array in arrays) {
    buffer.add(array);
  }
  return buffer.toBytes();
}

dynamic build_ack_info_from_ranges(flatRanges, ecnStats, ackDelay) {
  if (!flatRanges || flatRanges.length == 0) return null;
  if (flatRanges.length % 2 != 0)
    throw Exception("flatRanges must be in [from, to, ...] pairs");

  var ranges = [];
  for (var i = 0; i < flatRanges.length; i += 2) {
    var from = flatRanges[i];
    var to = flatRanges[i + 1];
    if (to < from) throw Exception("Range end must be >= start");
    ranges.add((start: from, end: to));
  }

  // Sort ranges from highest to lowest end
  ranges.sort((a, b) => b.end - a.end);

  // Merge overlapping or adjacent ranges
  var merged = [ranges[0]];
  for (var i = 1; i < ranges.length; i++) {
    var last = merged[merged.length - 1];
    var curr = ranges[i];
    if (curr.end >= last.start - 1) {
      // Merge them
      last.start = min(last.start, curr.start);
    } else {
      merged.add(curr);
    }
  }

  var largest = merged[0].end;
  var firstRange = largest - merged[0].start;
  var ackRanges = [];

  for (var i = 1; i < merged.length; i++) {
    var gap = merged[i - 1].start - merged[i].end - 1;
    var length = merged[i].end - merged[i].start;
    ackRanges.add({gap: gap, length: length});
  }

  return (
    type: 'ack',
    largest: largest,
    delay: ackDelay ?? 0,
    firstRange: firstRange,
    ranges: ackRanges,
    ecn: ecnStats
        ? (
            ect0: ecnStats.ect0 ?? 0,
            ect1: ecnStats.ect1 ?? 0,
            ce: ecnStats.ce ?? 0,
          )
        : null,
  );
}

dynamic build_ack_info_from_ranges2(flatRanges, ecnStats, ackDelay) {
  if (!flatRanges || flatRanges.length == 0) return null;
  if (flatRanges.length % 2 != 0)
    throw Exception("flatRanges must be in [from, to, ...] pairs");

  // בניית טווחים מלאים
  var ranges = [];
  for (var i = 0; i < flatRanges.length; i += 2) {
    var from = flatRanges[i];
    var to = flatRanges[i + 1];
    if (to < from) throw Exception("Range end must be >= start");
    ranges.add((start: from, end: to));
  }

  // ממיינים מהגדול לקטן לפי end
  ranges.sort((a, b) {
    return b.end - a.end;
  });

  // הסרת טווחים חופפים או לא חוקיים
  for (var i = 1; i < ranges.length; i++) {
    if (ranges[i].end >= ranges[i - 1].start) {
      throw Exception("Overlapping ranges are not allowed");
    }
  }

  // התחלת ack מהטווח הגבוה ביותר
  var largest = ranges[0].end;
  var firstRange = largest - ranges[0].start;

  var ackRanges = [];
  var runningEnd = ranges[0].start - 1;

  for (var i = 1; i < ranges.length; i++) {
    var gap = runningEnd - ranges[i].end - 1;
    var length = ranges[i].end - ranges[i].start;

    // בדיקה אם הבלוק הבא יגלוש מתחת ל־0
    var nextEnd = runningEnd - (gap + 1 + length);
    if (nextEnd < 0) {
      print("Skipped range due to underflow risk: ${ranges[i]}");
      continue; // לא מוסיפים את הטווח הזה
    }

    ackRanges.add({gap: gap, length: length});
    runningEnd = ranges[i].start - 1;
  }

  var frame = (
    type: 'ack',
    largest: largest,
    delay: ackDelay ?? 0,
    firstRange: firstRange,
    ranges: ackRanges,
    ecn: ecnStats
        ? (
            ect0: ecnStats.ect0 ?? 0,
            ect1: ecnStats.ect1 ?? 0,
            ce: ecnStats.ce ?? 0,
          )
        : null,
  );

  return frame;
}

dynamic quic_acked_info_to_ranges(ackFrame) {
  var flatRanges = [];

  if (!ackFrame || ackFrame.type != 'ack') return flatRanges;

  var largest = ackFrame.largest;
  var firstRange = ackFrame.firstRange;

  // טווח ראשון: [largest - firstRange, largest]
  var rangeEnd = largest;
  var rangeStart = rangeEnd - firstRange;
  flatRanges.addAll([rangeStart, rangeEnd]);

  // נתחיל לבנות את שאר הטווחים לפי gap+length
  var ranges = ackFrame.ranges ?? [];
  for (var i = 0; i < ranges.length; i++) {
    var (gap, length) = ranges[i];

    // מעבר אחורה לפי gap
    rangeEnd = rangeStart - 1 - gap;
    rangeStart = rangeEnd - length;

    flatRanges.addAll([rangeStart, rangeEnd]);
  }

  return flatRanges;
}

bool arraybufferEqual(Uint8List buf1, Uint8List buf2) {
  //if (buf1 === buf2) {
  //return true;
  //}

  if (buf1.length != buf2.length) {
    return false;
  }

  var view1 = ByteData.sublistView(buf1);
  var view2 = ByteData.sublistView(buf2);

  for (int i = 0; i < buf1.length; i++) {
    if (view1.getUint8(i) != view2.getUint8(i)) {
      return false;
    }
  }

  return true;
}
