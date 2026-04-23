import 'dart:typed_data';

abstract class QuicFrame {}

class CryptoFrame extends QuicFrame {
  final int offset;
  final Uint8List data;

  CryptoFrame({required this.offset, required this.data});
}

class AckFrame extends QuicFrame {
  final int largest;
  final int delay;
  final int firstRange;
  final List<dynamic> ranges;
  final dynamic ecn;

  AckFrame({
    required this.largest,
    required this.delay,
    required this.firstRange,
    required this.ranges,
    this.ecn,
  });
}
