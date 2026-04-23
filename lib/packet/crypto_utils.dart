// Simple AES-128-ECB implementation wrapper (JS: aes128ecb)
import 'dart:typed_data';

// ignore: depend_on_referenced_packages
import 'package:pointycastle/export.dart';

import '../cipher/aes_gcm.dart';
// import 'ciphers/aes_gcm.dart';

Uint8List aesEcbEncryptPrimitive({
  required Uint8List key,
  required Uint8List plaintext,
}) {
  final block = AESEngine()..init(true, KeyParameter(key));

  final input = plaintext.sublist(0);

  final out = block.process(input);
  return out;
}

Uint8List aes128Ecb(Uint8List sample, Uint8List hpKey) {
  if (hpKey.length != 16) {
    throw ArgumentError("AES-128-ECB key must be 16 bytes.");
  }
  // This calls the generic ECB function with the 16-byte key
  return aesEcbEncrypt(hpKey, sample);
}

/// Performs AES in ECB mode for Header Protection.
Uint8List aesEcbEncrypt(Uint8List keyBytes, Uint8List plaintext) {
  if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
    throw ArgumentError("Invalid AES key size: ${keyBytes.length} bytes.");
  }

  // The plaintext for header protection MUST be 16 bytes.
  if (plaintext.length % 16 != 0) {
    throw ArgumentError("Plaintext length must be a multiple of 16 bytes.");
  }

  // Perform ECB encryption (Placeholder for crypto library function)
  final encrypted = aesEcbEncryptPrimitive(key: keyBytes, plaintext: plaintext);
  return encrypted;
}

/// Performs raw AES-GCM decryption (equivalent to JS `aes_gcm_decrypt`).
/// This function is not QUIC-specific as it takes a pre-calculated `nonce`.
Uint8List? aesGcmDecrypt(
  Uint8List ciphertext,
  Uint8List tag,
  Uint8List key,
  Uint8List nonce,
  Uint8List aad,
) {
  try {
    if (key.length != 16 && key.length != 32) {
      throw Exception(
        "Unsupported key length: ${key.length}. Must be 16 or 32 bytes.",
      );
    }

    // Perform Decryption (Placeholder for crypto library function)
    final decrypted = aesGcmDecryptPrimitive(key, nonce, ciphertext, tag, aad);

    //print("✅ Decryption success!");
    return decrypted;
  } catch (e, st) {
    print("Decryption failed: $e");
    print(st);
    return null;
  }
}

Uint8List aesGcmDecryptPrimitive(
  Uint8List key,
  Uint8List nonce,
  Uint8List ciphertext,
  Uint8List tag,
  Uint8List aad,
) {
  return decrypt(
    encryptionKey: key,
    ciphertextWithAuthTag: Uint8List.fromList([...ciphertext, ...tag]),
    nonce: nonce,
    aead: aad,
  );
}

/// Calculates the QUIC AEAD nonce.
/// Nonce is computed as IV XOR (big-endian 64-bit Packet Number).
/// The IV is 12 bytes. The 64-bit Packet Number is left-padded with zeros
/// and XORed with the rightmost 8 bytes of the IV.
Uint8List computeNonce(Uint8List iv, int packetNumber) {
  if (iv.length != 12) {
    throw ArgumentError("IV must be 12 bytes for QUIC AEAD.");
  }

  // Create a mutable copy of the IV
  final nonce = Uint8List.fromList(iv);

  // Create an 8-byte buffer for the packet number (64-bit, big-endian)
  final pnBuffer = Uint8List(8);

  // Use ByteData to safely write the 64-bit integer in Big Endian format.
  final byteData = ByteData(8);
  byteData.setUint64(0, packetNumber, Endian.big);

  // Copy to pnBuffer
  pnBuffer.setAll(0, byteData.buffer.asUint8List());

  // XOR the rightmost 8 bytes of the IV (indices 4-11) with the 8 bytes of pnBuffer.
  // The first 4 bytes of the 12-byte IV remain untouched.
  for (var i = 0; i < 8; i++) {
    // pnBuffer[i] is byte 0 to 7 of the 64-bit packet number
    // nonce[i + 4] is byte 4 to 11 of the 12-byte IV/Nonce
    nonce[i + 4] ^= pnBuffer[i];
  }

  return nonce;
}

/// Performs AES-GCM encryption following the QUIC nonce construction.
Uint8List? aeadEncrypt(
  Uint8List key,
  Uint8List iv,
  int packetNumber,
  Uint8List plaintext,
  Uint8List aad,
) {
  try {
    // 1. Determine Key length
    if (key.length != 16 && key.length != 32) {
      throw Exception(
        "Unsupported key length: ${key.length}. Must be 16 or 32 bytes.",
      );
    }

    // 2. Compute Nonce
    final nonce = computeNonce(iv, packetNumber);

    // 3. Perform Encryption (This needs a proper AEAD encrypt primitive)
    // Since the JS function returns the combined ciphertext+tag, we need a helper
    // that produces both the ciphertext and the 16-byte tag.

    // This part is highly dependent on the Dart crypto library used.
    // For simplicity, we assume an encrypt primitive that returns a combined result.
    // NOTE: For GCM, the primitive must return (ciphertext + tag).

    // --- Placeholder for combined encryption primitive ---
    Uint8List combinedCiphertextTag(
      Uint8List key,
      Uint8List nonce,
      Uint8List plaintext,
      Uint8List aad,
    ) {
      final encrypted = encrypt(
        encryptionKey: key,
        message: plaintext,
        nonce: nonce,
        aead: aad,
      );
      // return Uint8List.fromList([...aad, ...encrypted]);
      return encrypted;
    }
    // --- End Placeholder ---

    final combined = combinedCiphertextTag(key, nonce, plaintext, aad);
    return combined;
  } catch (e, st) {
    print("AEAD Encryption failed: $e");
    print(st);
    return null;
  }
}
