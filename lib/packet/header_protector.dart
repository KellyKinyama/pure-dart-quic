// TODO Implement this library.
// NOTE: The following required functions must be implemented (or mocked) elsewhere:
// Uint8List aes128Ecb(Uint8List sample, Uint8List hpKey);
// VarIntReadResult? readVarInt(Uint8List array, int offset);
// int decodeAndExpandPacketNumber(Uint8List array, int offset, int pnLength, int largestReceived);
// Uint8List computeNonce(Uint8List iv, int packetNumber);
// Uint8List? aesGcmDecrypt(Uint8List ciphertext, Uint8List tag, Uint8List key, Uint8List nonce, Uint8List aad);
import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'crypto_utils.dart';

int decodeTruncatedPN(Uint8List array, int offset, int length) {
  int val = 0;
  for (int i = 0; i < length; i++) {
    val = (val << 8) | array[offset + i];
  }
  return val;
}

/// Reverses the Header Protection mechanism, unmasking the first header byte
/// and the Packet Number field.
///
/// The [array] is modified in place.
/// Returns the Packet Number Length (1, 2, 3, or 4 bytes).
int removeHeaderProtection({
  required Uint8List array,
  required int pnOffset,
  required Uint8List hpKey,
}) {
  if (array.isEmpty) {
    throw StateError("Packet is empty");
  }

  // Header form bit is NOT header-protected, so this is safe now.
  final isShort = (array[0] & 0x80) == 0;

  const sampleLength = 16;
  final sampleOffset = pnOffset + 4;

  if (sampleOffset + sampleLength > array.length) {
    throw StateError(
      "Not enough bytes for header protection sample "
      "(need ${sampleOffset + sampleLength}, have ${array.length})",
    );
  }

  final sample = array.sublist(sampleOffset, sampleOffset + sampleLength);

  // IMPORTANT:
  // Use the SAME helper/signature as the encrypt path.
  final maskFull = aesEcbEncrypt(hpKey, sample);
  final mask = maskFull.sublist(0, 5);

  // ------------------------------------------------------------
  // Unmask first byte
  // ------------------------------------------------------------
  if (isShort) {
    // Short header: unmask low 5 bits
    array[0] ^= (mask[0] & 0x1f);

    // Reserved bits for short header are bits 4-3 and MUST be zero
    final reservedBits = (array[0] >> 3) & 0x03;
    if (reservedBits != 0) {
      throw StateError(
        "Invalid short-header reserved bits after HP removal: "
        "${reservedBits.toRadixString(2).padLeft(2, '0')} "
        "(firstByte=0x${array[0].toRadixString(16)})",
      );
    }
  } else {
    // Long header: unmask low 4 bits
    array[0] ^= (mask[0] & 0x0f);

    // Reserved bits for long header are bits 3-2 and MUST be zero
    final reservedBits = (array[0] >> 2) & 0x03;
    if (reservedBits != 0) {
      throw StateError(
        "Invalid long-header reserved bits after HP removal: "
        "${reservedBits.toRadixString(2).padLeft(2, '0')} "
        "(firstByte=0x${array[0].toRadixString(16)})",
      );
    }
  }

  // ------------------------------------------------------------
  // Determine packet number length from unmasked first byte
  // ------------------------------------------------------------
  final pnLength = (array[0] & 0x03) + 1;

  if (pnOffset + pnLength > array.length) {
    throw StateError(
      "Packet number field extends beyond packet length after HP removal "
      "(pnOffset=$pnOffset, pnLength=$pnLength, packetLen=${array.length})",
    );
  }

  // ------------------------------------------------------------
  // Unmask packet number bytes
  // ------------------------------------------------------------
  for (int i = 0; i < pnLength; i++) {
    array[pnOffset + i] ^= mask[1 + i];
  }

  return pnLength;
}

/// Applies Header Protection (XORing the first byte and the Packet Number)
/// using the result of AES-ECB(HP Key, Sample).
Uint8List applyHeaderProtection(
  Uint8List packet,
  int pnOffset,
  Uint8List hpKey,
  int pnLength,
) {
  // QUIC Header Protection Sample is 16 bytes starting at pnOffset + 4
  const sampleLength = 16;
  if (pnOffset + 4 + sampleLength > packet.length) {
    throw Exception("Not enough bytes for header protection sample");
  }

  // 1. Get sample
  final sample = packet.sublist(pnOffset + 4, pnOffset + 4 + sampleLength);

  // 2. Encrypt sample using AES-ECB
  final maskFull = aesEcbEncrypt(hpKey, sample);
  final mask = maskFull.sublist(0, 5); // Use the first 5 bytes of the output

  // Create a mutable copy of the packet
  final resultPacket = Uint8List.fromList(packet);

  // 3. Apply mask to the first byte (Header Type)
  final firstByte = resultPacket[0];
  final isLongHeader = (firstByte & 0x80) != 0;

  if (isLongHeader) {
    // Long Header: Only XOR the lowest 4 bits (Version Specific + Reserved + Packet Number Length)
    resultPacket[0] ^= (mask[0] & 0x0f);
  } else {
    // Short Header: Only XOR the lowest 5 bits (Key Phase + Reserved + Packet Number Length)
    resultPacket[0] ^= (mask[0] & 0x1f);
  }

  // 4. Apply mask to the Packet Number field (pnLength bytes)
  for (var i = 0; i < pnLength; i++) {
    resultPacket[pnOffset + i] ^= mask[1 + i];
  }

  return resultPacket;
}

void main() {
  final hpKey = Uint8List.fromList(
    HEX.decode("6df4e9d737cdf714711d7c617ee82981"),
  );
  final packNumLength = removeHeaderProtection(
    array: quickPacket,
    pnOffset: 23,
    hpKey: hpKey,
    // isShort: false,
  );

  print("Packet number lemgth: $packNumLength");
}

final quickPacket = Uint8List.fromList([
  0xcd,
  0x00,
  0x00,
  0x00,
  0x01,
  0x08,
  0x00,
  0x01,
  0x02,
  0x03,
  0x04,
  0x05,
  0x06,
  0x07,
  0x05,
  0x63,
  0x5f,
  0x63,
  0x69,
  0x64,
  0x00,
  0x41,
  0x03,
  0x98,
  0x1c,
  0x36,
  0xa7,
  0xed,
  0x78,
  0x71,
  0x6b,
  0xe9,
  0x71,
  0x1b,
  0xa4,
  0x98,
  0xb7,
  0xed,
  0x86,
  0x84,
  0x43,
  0xbb,
  0x2e,
  0x0c,
  0x51,
  0x4d,
  0x4d,
  0x84,
  0x8e,
  0xad,
  0xcc,
  0x7a,
  0x00,
  0xd2,
  0x5c,
  0xe9,
  0xf9,
  0xaf,
  0xa4,
  0x83,
  0x97,
  0x80,
  0x88,
  0xde,
  0x83,
  0x6b,
  0xe6,
  0x8c,
  0x0b,
  0x32,
  0xa2,
  0x45,
  0x95,
  0xd7,
  0x81,
  0x3e,
  0xa5,
  0x41,
  0x4a,
  0x91,
  0x99,
  0x32,
  0x9a,
  0x6d,
  0x9f,
  0x7f,
  0x76,
  0x0d,
  0xd8,
  0xbb,
  0x24,
  0x9b,
  0xf3,
  0xf5,
  0x3d,
  0x9a,
  0x77,
  0xfb,
  0xb7,
  0xb3,
  0x95,
  0xb8,
  0xd6,
  0x6d,
  0x78,
  0x79,
  0xa5,
  0x1f,
  0xe5,
  0x9e,
  0xf9,
  0x60,
  0x1f,
  0x79,
  0x99,
  0x8e,
  0xb3,
  0x56,
  0x8e,
  0x1f,
  0xdc,
  0x78,
  0x9f,
  0x64,
  0x0a,
  0xca,
  0xb3,
  0x85,
  0x8a,
  0x82,
  0xef,
  0x29,
  0x30,
  0xfa,
  0x5c,
  0xe1,
  0x4b,
  0x5b,
  0x9e,
  0xa0,
  0xbd,
  0xb2,
  0x9f,
  0x45,
  0x72,
  0xda,
  0x85,
  0xaa,
  0x3d,
  0xef,
  0x39,
  0xb7,
  0xef,
  0xaf,
  0xff,
  0xa0,
  0x74,
  0xb9,
  0x26,
  0x70,
  0x70,
  0xd5,
  0x0b,
  0x5d,
  0x07,
  0x84,
  0x2e,
  0x49,
  0xbb,
  0xa3,
  0xbc,
  0x78,
  0x7f,
  0xf2,
  0x95,
  0xd6,
  0xae,
  0x3b,
  0x51,
  0x43,
  0x05,
  0xf1,
  0x02,
  0xaf,
  0xe5,
  0xa0,
  0x47,
  0xb3,
  0xfb,
  0x4c,
  0x99,
  0xeb,
  0x92,
  0xa2,
  0x74,
  0xd2,
  0x44,
  0xd6,
  0x04,
  0x92,
  0xc0,
  0xe2,
  0xe6,
  0xe2,
  0x12,
  0xce,
  0xf0,
  0xf9,
  0xe3,
  0xf6,
  0x2e,
  0xfd,
  0x09,
  0x55,
  0xe7,
  0x1c,
  0x76,
  0x8a,
  0xa6,
  0xbb,
  0x3c,
  0xd8,
  0x0b,
  0xbb,
  0x37,
  0x55,
  0xc8,
  0xb7,
  0xeb,
  0xee,
  0x32,
  0x71,
  0x2f,
  0x40,
  0xf2,
  0x24,
  0x51,
  0x19,
  0x48,
  0x70,
  0x21,
  0xb4,
  0xb8,
  0x4e,
  0x15,
  0x65,
  0xe3,
  0xca,
  0x31,
  0x96,
  0x7a,
  0xc8,
  0x60,
  0x4d,
  0x40,
  0x32,
  0x17,
  0x0d,
  0xec,
  0x28,
  0x0a,
  0xee,
  0xfa,
  0x09,
  0x5d,
  0x08,
  0xb3,
  0xb7,
  0x24,
  0x1e,
  0xf6,
  0x64,
  0x6a,
  0x6c,
  0x86,
  0xe5,
  0xc6,
  0x2c,
  0xe0,
  0x8b,
  0xe0,
  0x99,
]);
