// lib/quic_ack.dart
import 'dart:typed_data';

import '../utils.dart';

//
// =============================================================
// VarInt (RFC 9000 §16) – Minimal implementation
// =============================================================
// Uint8List encodeVarInt(int v) {
//   if (v < 0x40) {
//     return Uint8List.fromList([v]);
//   } else if (v < 0x4000) {
//     return Uint8List.fromList([0x40 | (v >> 8), v & 0xff]);
//   } else if (v < 0x4000_0000) {
//     return Uint8List.fromList([
//       0x80 | (v >> 24),
//       (v >> 16) & 0xff,
//       (v >> 8) & 0xff,
//       v & 0xff,
//     ]);
//   } else {
//     return Uint8List.fromList([
//       0xC0 | (v >> 56),
//       (v >> 48) & 0xff,
//       (v >> 40) & 0xff,
//       (v >> 32) & 0xff,
//       (v >> 24) & 0xff,
//       (v >> 16) & 0xff,
//       (v >> 8) & 0xff,
//       v & 0xff,
//     ]);
//   }
// }

//
// =============================================================
// ACK Ranges
// =============================================================
class QuicAckRange {
  final int gap;
  final int rangeLength;

  QuicAckRange({required this.gap, required this.rangeLength});
}

//
// =============================================================
// ACK Frame with optional ECN support
// RFC 9000 §19.3
// =============================================================
class QuicAckFrame {
  final int largest;
  final int ackDelay;
  final int firstRange;
  final List<QuicAckRange> additionalRanges;

  // ✅ ECN counters
  final int? ect0;
  final int? ect1;
  final int? ce;

  QuicAckFrame({
    required this.largest,
    required this.ackDelay,
    required this.firstRange,
    required this.additionalRanges,
    this.ect0,
    this.ect1,
    this.ce,
  });

  bool get hasEcn => ect0 != null || ect1 != null || ce != null;

  Uint8List encode() {
    final out = BytesBuilder();

    // ✅ ACK type (0x02 = no ECN, 0x03 = ECN-enabled)
    out.addByte(hasEcn ? 0x03 : 0x02);

    out.add(writeVarInt(largest));
    out.add(writeVarInt(ackDelay));
    out.add(writeVarInt(additionalRanges.length));
    out.add(writeVarInt(firstRange));

    // Additional ranges (gap + length)
    for (final r in additionalRanges) {
      out.add(writeVarInt(r.gap));
      out.add(writeVarInt(r.rangeLength));
    }

    // ✅ Append ECN counts if present
    if (hasEcn) {
      out.add(writeVarInt(ect0 ?? 0));
      out.add(writeVarInt(ect1 ?? 0));
      out.add(writeVarInt(ce ?? 0));
    }

    return out.toBytes();
  }
}

//
// =============================================================
// Build multi-range ACK from received PN set
// =============================================================
// QuicAckFrame buildAckFromSet(
//   Set<int> received, {
//   int ackDelayMicros = 0,
//   int? ect0,
//   int? ect1,
//   int? ce,
// }) {
//   if (received.isEmpty) {
//     return QuicAckFrame(
//       largest: 0,
//       ackDelay: 0,
//       firstRange: 0,
//       additionalRanges: [],
//       ect0: ect0,
//       ect1: ect1,
//       ce: ce,
//     );
//   }

//   final sorted = received.toList()..sort();

//   int largest = sorted.last;
//   int idx = sorted.length - 1;

//   int firstRangeLen = 0;

//   // First range (largest continuous run downward)
//   while (idx > 0 && (sorted[idx - 1] == sorted[idx] - 1)) {
//     firstRangeLen++;
//     idx--;
//   }

//   // Additional gap-based ranges
//   List<QuicAckRange> ranges = [];
//   int cursor = idx - 1;

//   while (cursor >= 0) {
//     int gap = sorted[cursor + 1] - sorted[cursor] - 1;
//     if (gap < 0) gap = 0;

//     int start = cursor;
//     while (cursor > 0 && sorted[cursor - 1] == sorted[cursor] - 1) {
//       cursor--;
//     }

//     int length = start - cursor;

//     ranges.add(QuicAckRange(gap: gap, rangeLength: length));

//     cursor--;
//   }

//   return QuicAckFrame(
//     largest: largest,
//     ackDelay: ackDelayMicros,
//     firstRange: firstRangeLen,
//     additionalRanges: ranges,
//     ect0: ect0,
//     ect1: ect1,
//     ce: ce,
//   );
// }

// lib/quic_ack.dart
// import 'dart:typed_data';

//
// =============================================================
// VarInt (RFC 9000 §16) – Minimal implementation
// =============================================================
// Uint8List encodeVarInt(int v) {
//   if (v < 0) {
//     throw ArgumentError('QUIC varint must be non-negative: $v');
//   }

//   if (v < 0x40) {
//     // 1-byte: 00xxxxxx
//     return Uint8List.fromList([v & 0x3f]);
//   } else if (v < 0x4000) {
//     // 2-byte: 01xxxxxx xxxxxxxx
//     return Uint8List.fromList([
//       0x40 | ((v >> 8) & 0x3f),
//       v & 0xff,
//     ]);
//   } else if (v < 0x40000000) {
//     // 4-byte: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
//     return Uint8List.fromList([
//       0x80 | ((v >> 24) & 0x3f),
//       (v >> 16) & 0xff,
//       (v >> 8) & 0xff,
//       v & 0xff,
//     ]);
//   } else if (v < 0x4000000000000000) {
//     // 8-byte: 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
//     //         xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
//     return Uint8List.fromList([
//       0xC0 | ((v >> 56) & 0x3f),
//       (v >> 48) & 0xff,
//       (v >> 40) & 0xff,
//       (v >> 32) & 0xff,
//       (v >> 24) & 0xff,
//       (v >> 16) & 0xff,
//       (v >> 8) & 0xff,
//       v & 0xff,
//     ]);
//   } else {
//     throw ArgumentError('QUIC varint out of range: $v');
//   }
// }

//
// =============================================================
// ACK Ranges
// =============================================================
// class QuicAckRange {
//   final int gap;
//   final int rangeLength;

//   QuicAckRange({
//     required this.gap,
//     required this.rangeLength,
//   });
// }

//
// =============================================================
// ACK Frame with optional ECN support
// RFC 9000 §19.3
// =============================================================
// class QuicAckFrame {
//   final int largest;
//   final int ackDelay;
//   final int firstRange;
//   final List<QuicAckRange> additionalRanges;

//   // Optional ECN counters
//   final int? ect0;
//   final int? ect1;
//   final int? ce;

//   QuicAckFrame({
//     required this.largest,
//     required this.ackDelay,
//     required this.firstRange,
//     required this.additionalRanges,
//     this.ect0,
//     this.ect1,
//     this.ce,
//   });

//   bool get hasEcn => ect0 != null || ect1 != null || ce != null;

//   Uint8List encode() {
//     final out = BytesBuilder();

//     // 0x02 = ACK
//     // 0x03 = ACK_ECN
//     out.addByte(hasEcn ? 0x03 : 0x02);

//     out.add(encodeVarInt(largest));
//     out.add(encodeVarInt(ackDelay));
//     out.add(encodeVarInt(additionalRanges.length));
//     out.add(encodeVarInt(firstRange));

//     // Additional ranges: gap + rangeLength
//     for (final r in additionalRanges) {
//       out.add(encodeVarInt(r.gap));
//       out.add(encodeVarInt(r.rangeLength));
//     }

//     // Optional ECN counters
//     if (hasEcn) {
//       out.add(encodeVarInt(ect0 ?? 0));
//       out.add(encodeVarInt(ect1 ?? 0));
//       out.add(encodeVarInt(ce ?? 0));
//     }

//     return out.toBytes();
//   }
// }

//
// =============================================================
// Build multi-range ACK from received PN set
//
// Notes:
// - firstRange = size_of_first_contiguous_range - 1
// - rangeLength = size_of_range - 1
// - gap = number_of_missing_packets_between_ranges - 1
// =============================================================
QuicAckFrame buildAckFromSet(
  Set<int> received, {
  int ackDelayMicros = 0,
  int ackDelayExponent = 3, // default QUIC exponent if peer didn't override
  int? ect0,
  int? ect1,
  int? ce,
}) {
  if (received.isEmpty) {
    return QuicAckFrame(
      largest: 0,
      ackDelay: 0,
      firstRange: 0,
      additionalRanges: [],
      ect0: ect0,
      ect1: ect1,
      ce: ce,
    );
  }

  final sorted = received.toList()..sort();

  final largest = sorted.last;
  int idx = sorted.length - 1;

  // ----------------------------------------------------------
  // First ACK range:
  // largest contiguous run downward from the largest packet
  // firstRange is encoded as range_size - 1
  // ----------------------------------------------------------
  int firstRangeLen = 0;
  while (idx > 0 && sorted[idx - 1] == sorted[idx] - 1) {
    firstRangeLen++;
    idx--;
  }

  // ----------------------------------------------------------
  // Additional ACK ranges
  // ----------------------------------------------------------
  final ranges = <QuicAckRange>[];
  int cursor = idx - 1;

  // previousRangeSmallest tracks the smallest packet number
  // in the previously emitted ACK range.
  int previousRangeSmallest = largest - firstRangeLen;

  while (cursor >= 0) {
    final rangeEnd = sorted[cursor];

    // Walk backward to find the contiguous start of this range
    int rangeStartIndex = cursor;
    while (rangeStartIndex > 0 &&
        sorted[rangeStartIndex - 1] == sorted[rangeStartIndex] - 1) {
      rangeStartIndex--;
    }

    final rangeStartPn = sorted[rangeStartIndex];

    // Number of packets in this contiguous range
    final rangeSize = rangeEnd - rangeStartPn + 1;

    // QUIC ACK rangeLength = range_size - 1
    final rangeLength = rangeSize - 1;

    // Missing packets between ranges:
    // previousRangeSmallest ... next rangeEnd
    //
    // Example:
    // previous smallest = 98
    // next range end    = 95
    // missing packets   = 97,96 => count = 2
    final missingCount = previousRangeSmallest - rangeEnd - 1;

    // QUIC gap field = missingCount - 1
    final gap = missingCount - 1;

    if (missingCount <= 0 || gap < 0) {
      throw StateError(
        'Invalid ACK range construction: '
        'previousSmallest=$previousRangeSmallest '
        'rangeEnd=$rangeEnd missingCount=$missingCount gap=$gap',
      );
    }

    ranges.add(QuicAckRange(gap: gap, rangeLength: rangeLength));

    previousRangeSmallest = rangeStartPn;
    cursor = rangeStartIndex - 1;
  }

  // QUIC ACK delay is encoded in units of 2^ackDelayExponent microseconds
  final encodedAckDelay = ackDelayMicros >> ackDelayExponent;

  return QuicAckFrame(
    largest: largest,
    ackDelay: encodedAckDelay,
    firstRange: firstRangeLen,
    additionalRanges: ranges,
    ect0: ect0,
    ect1: ect1,
    ce: ce,
  );
}
