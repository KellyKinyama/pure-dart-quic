// import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/modes/gcm.dart';

Uint8List decrypt({
  required Uint8List encryptionKey,
  required Uint8List ciphertextWithAuthTag,
  required Uint8List nonce,
  required Uint8List aead,
}) {
  // final msg = utf8.encode(
  //   'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.',
  // );

  final int aeadAuthTagLen =
      16; // Defined in protectionprofiles.go for AES_128_GCM
  final params = AEADParameters(
    KeyParameter(encryptionKey),
    aeadAuthTagLen * 8,
    nonce,
    aead,
  );
  // final GCMBlockCipher blockCipherEncrypter = GCMBlockCipher(AESEngine());
  // blockCipherEncrypter.init(true, params); //
  // final ciphertextWithAuthTag = blockCipherEncrypter.process(msg);

  //  final AESEngine blockCipherDecrypter = AESEngine();
  final GCMBlockCipher blockCipherDecrypter = GCMBlockCipher(AESEngine());
  blockCipherDecrypter.init(false, params); // false for decryption

  final Uint8List payloadAndTag = Uint8List.fromList(ciphertextWithAuthTag);
  // print("Header bytes in decryption: $headerBytes");

  // try {
  final decryptedBytes = blockCipherDecrypter.process(payloadAndTag);
  return decryptedBytes;
  // return Uint8List.fromList([...headerBytes, ...decryptedBytes]);
  // } catch (e) {
  //   throw Exception("SRTP GCM decryption failed: $e");
  // }
}

Uint8List encrypt({
  required Uint8List encryptionKey,
  required Uint8List message,
  required Uint8List nonce,
  required Uint8List aead,
}) {
  // print("encrypt: nonce: $nonce");
  // final msg = utf8.encode(
  //   'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.',
  // );

  final int aeadAuthTagLen =
      16; // Defined in protectionprofiles.go for AES_128_GCM
  final params = AEADParameters(
    KeyParameter(encryptionKey),
    aeadAuthTagLen * 8,
    nonce,
    aead,
  );
  final GCMBlockCipher blockCipherEncrypter = GCMBlockCipher(AESEngine());
  blockCipherEncrypter.init(true, params); //
  final ciphertextWithAuthTag = blockCipherEncrypter.process(message);
  return ciphertextWithAuthTag;
}

// void seal() {
//   final msg = utf8.encode(
//     'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.',
//   );

//   final int aeadAuthTagLen =
//       16; // Defined in protectionprofiles.go for AES_128_GCM
//   final params = AEADParameters(
//     KeyParameter(encryptionKey),
//     aeadAuthTagLen * 8,
//     nonce,
//     aead,
//   );
//   final GCMBlockCipher blockCipherEncrypter = GCMBlockCipher(AESEngine());
//   blockCipherEncrypter.init(true, params); //
//   final ciphertextWithAuthTag = blockCipherEncrypter.process(msg);

//   //  final AESEngine blockCipherDecrypter = AESEngine();
//   final GCMBlockCipher blockCipherDecrypter = GCMBlockCipher(AESEngine());
//   blockCipherDecrypter.init(false, params); // false for decryption

//   final Uint8List payloadAndTag = Uint8List.fromList(ciphertextWithAuthTag);
//   // print("Header bytes in decryption: $headerBytes");

//   // try {
//   final decryptedBytes = blockCipherDecrypter.process(payloadAndTag);

//   // return Uint8List.fromList([...headerBytes, ...decryptedBytes]);
//   // } catch (e) {
//   //   throw Exception("SRTP GCM decryption failed: $e");
//   // }
// }

void main() {
  // seal();
}

// final nonce = Uint8List.fromList([0, 0, 0, 0, 0, 0, 19, 55]);
// final aead = Uint8List.fromList([
//   68,
//   111,
//   110,
//   101,
//   99,
//   32,
//   105,
//   110,
//   32,
//   118,
//   101,
//   108,
//   105,
//   116,
//   32,
//   110,
//   101,
//   113,
//   117,
//   101,
//   46,
// ]);
// final encryptionKey = Uint8List.fromList([
//   34,
//   167,
//   97,
//   50,
//   49,
//   13,
//   176,
//   208,
//   221,
//   157,
//   63,
//   139,
//   99,
//   160,
//   240,
//   30,
// ]);
