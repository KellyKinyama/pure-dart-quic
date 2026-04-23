import 'dart:typed_data';
// finished.dart
// import 'dart:typed_data';
import '../buffer.dart';
import 'tls_msg.dart';

Uint8List buildFinishedMessage(Uint8List verifyData) {
  final length = verifyData.length;

  final header = Uint8List.fromList([
    0x14, // Finished
    (length >> 16) & 0xff,
    (length >> 8) & 0xff,
    length & 0xff,
  ]);

  return Uint8List.fromList([...header, ...verifyData]);
}

class FinishedMessage extends TlsHandshakeMessage {
  final Uint8List verifyData;

  FinishedMessage(this.verifyData) : super(0x14);

  // ---------------------------------------------------------
  // ✅ PARSER
  // ---------------------------------------------------------
  static FinishedMessage parse(QuicBuffer buf) {
    final data = buf.pullBytes(buf.remaining);
    return FinishedMessage(data);
  }

  // ---------------------------------------------------------
  // ✅ BUILDER  (matches JS build_finished)
  // ---------------------------------------------------------
  Uint8List build() {
    final body = verifyData;

    final header = [
      msgType,
      (body.length >> 16) & 0xFF,
      (body.length >> 8) & 0xFF,
      body.length & 0xFF,
    ];

    return Uint8List.fromList([...header, ...body]);
  }

  @override
  String toString() => "✅ FinishedMessage(len=${verifyData.length})";
}
