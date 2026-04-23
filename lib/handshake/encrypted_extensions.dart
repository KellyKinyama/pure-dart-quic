// encrypted_extensions.dart
import 'dart:typed_data';
import '../buffer.dart';
import 'tls_msg.dart';

class EncryptedExtensions extends TlsHandshakeMessage {
  final List<TlsExtension> extensions;

  EncryptedExtensions({required this.extensions})
    : super(0x08); // handshake type

  // ---------------------------------------------------------
  // ✅ PARSER
  // body format:
  //   uint16 extensions_length
  //   Extension extensions[extensions_length]
  // ---------------------------------------------------------
  static EncryptedExtensions parse(QuicBuffer buf) {
    final extTotalLen = buf.pullUint16();
    final end = buf.readOffset + extTotalLen;

    final exts = <TlsExtension>[];

    while (buf.readOffset < end) {
      final type = buf.pullUint16();
      final len = buf.pullUint16();
      final data = buf.pullBytes(len);
      exts.add(TlsExtension(type: type, length: len, data: data));
    }

    return EncryptedExtensions(extensions: exts);
  }

  // ---------------------------------------------------------
  // ✅ BUILDER (like JS build_encrypted_extensions)
  // ---------------------------------------------------------
  Uint8List build() {
    final extBytes = BytesBuilder();

    for (final ext in extensions) {
      extBytes.add([(ext.type >> 8) & 0xFF, ext.type & 0xFF]);
      extBytes.add([(ext.data.length >> 8) & 0xFF, ext.data.length & 0xFF]);
      extBytes.add(ext.data);
    }

    final extList = extBytes.toBytes();

    final body = BytesBuilder()
      ..add([(extList.length >> 8) & 0xFF, extList.length & 0xFF])
      ..add(extList);

    final bodyBytes = body.toBytes();
    final header = [
      msgType,
      (bodyBytes.length >> 16) & 0xFF,
      (bodyBytes.length >> 8) & 0xFF,
      bodyBytes.length & 0xFF,
    ];

    return Uint8List.fromList([...header, ...bodyBytes]);
  }

  @override
  String toString() => "✅ EncryptedExtensions(${extensions} extensions)";
}
