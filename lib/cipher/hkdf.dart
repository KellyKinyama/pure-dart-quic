// lib/hkdf.dart
import 'dart:convert';
import 'dart:typed_data';

// import 'package:pointycastle/export.dart';

// import 'prf.dart';

// import 'dart:convert';
// import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;

//hkdfExpandLabel expands a label as defined in RFC 8446, section 7.1.
// Uint8List hkdfExpandLabel(
//   // Digest hash,
//   Uint8List secret,
//   Uint8List context,
//   String label,
//   int length,
// ) {
//   final labelBytes = utf8.encode('tls13 $label');

//   final hkdfLabel = BytesBuilder();
//   hkdfLabel.addByte(length >> 8);
//   hkdfLabel.addByte(length & 0xff);
//   hkdfLabel.addByte(labelBytes.length);
//   hkdfLabel.add(labelBytes);
//   hkdfLabel.addByte(context.length);
//   hkdfLabel.add(context);

//   final prk = hkdfExtract(secret);
//   final okm = hkdfExpand(prk, hkdfLabel.toBytes(), length);

//   if (okm.length != length) {
//     throw Exception('quic: HKDF-Expand-Label invocation failed unexpectedly');
//   }
//   return okm;
// }

// Uint8List hkdfExpandLabel(
//   Uint8List secret, // This is the PRK and should be used directly
//   Uint8List context,
//   String label,
//   int length,
// ) {
//   final labelBytes = utf8.encode('tls13 $label');

//   final hkdfLabel = BytesBuilder();
//   hkdfLabel.addByte(length >> 8);
//   hkdfLabel.addByte(length & 0xff);
//   hkdfLabel.addByte(labelBytes.length);
//   hkdfLabel.add(labelBytes);
//   hkdfLabel.addByte(context.length);
//   hkdfLabel.add(context);

//   // INCORRECT LINE TO REMOVE:
//   // final prk = hkdfExtract(secret);

//   // CORRECTED: Use the 'secret' parameter directly in hkdfExpand.
//   final okm = hkdfExpand(secret, hkdfLabel.toBytes(), length);

//   if (okm.length != length) {
//     throw Exception('quic: HKDF-Expand-Label invocation failed unexpectedly');
//   }
//   return okm;
// }

// lib/go_quic/hkdf.dart

/// A robust, PointyCastle-based HKDF-Extract dynamic.
Uint8List hkdfExtract(Uint8List ikm, {required Uint8List salt}) {
  final hmac = pc.HMac(pc.SHA256Digest(), 64)..init(pc.KeyParameter(salt));
  return hmac.process(ikm);
}

/// A robust, PointyCastle-based HKDF-Expand dynamic.
Uint8List hkdfExpand({
  required Uint8List prk,
  required Uint8List info,
  required int outputLength,
}) {
  final hmac = pc.HMac(pc.SHA256Digest(), 64)..init(pc.KeyParameter(prk));
  final output = BytesBuilder();
  Uint8List t = Uint8List(0);

  for (int counter = 1; output.length < outputLength; counter++) {
    final input = BytesBuilder()
      ..add(t)
      ..add(info)
      ..addByte(counter);
    t = hmac.process(input.toBytes());
    output.add(t);
  }
  return output.toBytes().sublist(0, outputLength);
}

/// The standard hkdfExpandLabel dynamic.
// Uint8List hkdfExpandLabel(Uint8List secret, String label, int length) {
Uint8List hkdfExpandLabel({
  required Uint8List secret, // This is the PRK and should be used directly
  required Uint8List context,
  required String label,
  required int length,
}) {
  final labelBytes = utf8.encode('tls13 $label');
  final hkdfLabel = BytesBuilder()
    ..addByte(length >> 8)
    ..addByte(length & 0xff)
    ..addByte(labelBytes.length)
    ..add(labelBytes)
    ..addByte(context.length)
    ..add(context); // Context is empty

  // if (context.isEmpty) {
  //   hkdfLabel.addByte(0);
  // } else {
  //   hkdfLabel.add(context);
  // }
  return hkdfExpand(
    prk: secret,
    info: hkdfLabel.toBytes(),
    outputLength: length,
  );
}
