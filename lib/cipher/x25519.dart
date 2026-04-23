import 'dart:typed_data';

import 'package:x25519/x25519.dart';

Uint8List x25519ShareSecret({
  required Uint8List privateKey,
  required Uint8List publicKey,
}) {
  return X25519(privateKey, publicKey);
}
