import 'dart:typed_data';
import 'package:crypto/crypto.dart';

Uint8List createHash(Uint8List message) {
  return Uint8List.fromList(sha256.convert(message).bytes);
}

/// Computes HMAC-SHA256
Uint8List hmacSha256({required Uint8List key, required Uint8List data}) {
  var hmac = Hmac(sha256, key);
  return Uint8List.fromList(hmac.convert(data).bytes);
}
