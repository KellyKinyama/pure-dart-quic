// --- Required Helper Class ---
import 'dart:typed_data';

import 'package:hex/hex.dart';

// import '../quic_session.dart';
import '../utils.dart';
import 'crypto_utils.dart';
import 'header_protector.dart';
// import 'protocol.dart';
import 'quic_header.dart';

class QuicDecryptedPacket {
  final int packetNumber;
  final bool keyPhase;
  final Uint8List? plaintext; // Null if decryption/authentication fails
  QuicHeaderInfo? quicHeader;

  QuicDecryptedPacket({
    required this.packetNumber,
    required this.keyPhase,
    this.quicHeader,
    this.plaintext,
  });

  @override
  String toString() {
    // TODO: implement toString
    return """QuicDecryptedPacket{
      packetNumber: $packetNumber,
      keyPhase: $keyPhase,
      plaintext: ${plaintext != null ? HEX.encode(plaintext!.sublist(0, plaintext!.length < 10 ? plaintext!.length : 10)) : plaintext}
    }""";
  }
}

/// Parses, removes header protection, decrypts, and authenticates a QUIC packet.
///
/// Returns a [QuicDecryptedPacket] containing the plaintext and metadata, or `null`
/// if decryption/authentication fails.

QuicDecryptedPacket? decryptQuicPacketBytes(
  Uint8List array,
  Uint8List readKey,
  Uint8List readIv,
  Uint8List readHp,
  Uint8List dcid,
  int largestPn, {
  bool logging = true,
}) {
  final mutable = Uint8List.fromList(array);
  final firstByte = mutable[0];
  final isLong = (firstByte & 0x80) != 0;

  if (logging) {
    print('--- decryptQuicPacket keys ---');
    print('READ.key = ${HEX.encode(readKey)}');
    print('READ.iv  = ${HEX.encode(readIv)}');
    print('READ.hp  = ${HEX.encode(readHp)}');
    print('dcid     = ${HEX.encode(dcid)}');
    print('pkt[0]   = 0x${firstByte.toRadixString(16).padLeft(2, '0')}');
    print('pkt.len  = ${mutable.length}');
  }

  int pnOffset;
  int pnLength;
  late int packetNumber;
  late Uint8List ciphertext;
  late Uint8List tag;
  late Uint8List aad;
  late Uint8List nonce;

  try {
    if (isLong) {
      // ---- Long Header ----
      int offset = 1; // first byte
      offset += 4; // version

      final dcidLen = mutable[offset++];
      offset += dcidLen;

      final scidLen = mutable[offset++];
      offset += scidLen;

      final typeBits = (mutable[0] >> 4) & 0x03;
      if (typeBits == 0x00) {
        // Initial → token
        final t = readVarInt(mutable, offset)!;
        offset += t.byteLength + t.value;
      }

      // Length field
      final lenField = readVarInt(mutable, offset)!;
      offset += lenField.byteLength;
      pnOffset = offset;

      // ---- Header Protection ----
      pnLength = removeHeaderProtection(
        array: mutable,
        pnOffset: pnOffset,
        hpKey: readHp,
        // isShort: false,
      );

      // ✅ sanity check
      if (pnLength < 1 || pnLength > 4) {
        throw StateError('Invalid PN length: $pnLength');
      }

      // ✅ LOG unmasked first byte
      if (logging) {
        print(
          'Unmasked first byte: 0x${mutable[0].toRadixString(16).padLeft(2, '0')}',
        );
        print('Packet number offset: $pnOffset');
        print('Packet number length: $pnLength');
      }

      packetNumber = decodeAndExpandPacketNumber(
        mutable,
        pnOffset,
        pnLength,
        largestPn,
      );

      nonce = computeNonce(readIv, packetNumber);

      if (logging) {
        print('Packet number: $packetNumber');
        print('Nonce: ${HEX.encode(nonce)}');
      }

      // ---- Payload bounds (RFC‑correct) ----
      final payloadStart = pnOffset + pnLength;
      final payloadLength = lenField.value - pnLength;
      final payloadEnd = payloadStart + payloadLength;

      if (payloadEnd > mutable.length) {
        throw StateError('Truncated packet payload');
      }

      final payload = mutable.sublist(payloadStart, payloadEnd);

      if (payload.length < 16) {
        throw StateError('Encrypted payload too short');
      }

      ciphertext = payload.sublist(0, payload.length - 16);
      tag = payload.sublist(payload.length - 16);

      // ✅ AAD = header + PN (after HP removal)
      aad = mutable.sublist(0, payloadStart);
    } else {
      // ---- Short Header (1‑RTT) ----
      pnOffset = 1 + dcid.length;

      pnLength = removeHeaderProtection(
        array: mutable,
        pnOffset: pnOffset,
        hpKey: readHp,
        // isShort: true,
      );

      if (pnLength < 1 || pnLength > 4) {
        throw StateError('Invalid PN length: $pnLength');
      }

      if (logging) {
        print(
          'Unmasked first byte: 0x${mutable[0].toRadixString(16).padLeft(2, '0')}',
        );
        print('Packet number offset: $pnOffset');
        print('Packet number length: $pnLength');
      }

      packetNumber = decodeAndExpandPacketNumber(
        mutable,
        pnOffset,
        pnLength,
        largestPn,
      );

      nonce = computeNonce(readIv, packetNumber);

      if (logging) {
        print('Packet number: $packetNumber');
        print('Nonce: ${HEX.encode(nonce)}');
      }

      final payloadStart = pnOffset + pnLength;
      final payload = mutable.sublist(payloadStart);

      if (payload.length < 16) {
        throw StateError('Encrypted payload too short');
      }

      ciphertext = payload.sublist(0, payload.length - 16);
      tag = payload.sublist(payload.length - 16);
      aad = mutable.sublist(0, payloadStart);
    }
  } catch (e, st) {
    print('Decryption failed: $e');
    print(st);
    return null;
  }

  if (logging) {
    print('AAD (hex): ${HEX.encode(aad)}');
    print('Ciphertext+Tag len: ${ciphertext.length + tag.length}');
    print('Decrypting cipher text ...');
  }

  final plaintext = aesGcmDecrypt(ciphertext, tag, readKey, nonce, aad);
  if (plaintext == null) return null;

  if (logging) {
    print('✅ Payload decrypted successfully!');
    print(
      '✅ Recovered Message (Hex): ${HEX.encode(plaintext.take(16).toList())}',
    );
  }

  return QuicDecryptedPacket(
    packetNumber: packetNumber,
    keyPhase: false,
    plaintext: plaintext,
  );
}

int decodeAndExpandPacketNumber(
  Uint8List array,
  int offset,
  int pnLength,
  int largestReceived,
) {
  final truncated = decodePacketNumber(array, offset, pnLength);
  return expandPacketNumber(truncated, pnLength, largestReceived);
}

/// Decodes a truncated Packet Number from the byte array.
int decodePacketNumber(Uint8List array, int offset, int pnLength) {
  int value = 0;
  for (var i = 0; i < pnLength; i++) {
    // Dart handles the shift correctly without explicit masks like `| array[offset + i]`
    value = (value << 8) | array[offset + i];
  }
  return value;
}

int expandPacketNumber(int truncated, int pnLen, int largestReceived) {
  final pnWindow = 1 << (pnLen * 8);
  final pnHalf = pnWindow >> 1;
  final expected = largestReceived + 1;

  int candidate = (expected & ~(pnWindow - 1)) | truncated;

  if (candidate <= expected - pnHalf) {
    candidate += pnWindow;
  } else if (candidate > expected + pnHalf) {
    candidate -= pnWindow;
  }

  return candidate;
}

// /// Encrypts a QUIC packet and applies Header Protection.
// ///
// /// Combines the logic from `encrypt_quic_packet` and `encrypt_quic_packet2`
// /// with correct padding logic for AES-GCM (16-byte sample).
// Uint8List? encryptQuicPacket(
//   String packetType,
//   Uint8List encodedFrames,
//   Uint8List writeKey,
//   Uint8List writeIv,
//   Uint8List writeHp,
//   int packetNumber,
//   Uint8List dcid,
//   Uint8List scid,
//   Uint8List? token,
// ) {
//   // 1. Determine Packet Number Length
//   int pnLength;
//   if (packetNumber <= 0xff) {
//     pnLength = 1;
//   } else if (packetNumber <= 0xffff)
//     pnLength = 2;
//   else if (packetNumber <= 0xffffff)
//     pnLength = 3;
//   else
//     pnLength = 4;

//   // 2. Truncate Packet Number field to pnLength bytes (Big Endian)
//   final pnFull = ByteData(4);
//   pnFull.setUint32(0, packetNumber, Endian.big);
//   final packetNumberField = pnFull.buffer.asUint8List().sublist(4 - pnLength);

//   // 3. Initial calculation of payload length (frames + PN field + 16 byte GCM tag)
//   int unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
//   Uint8List lengthField = writeVarInt(unprotectedPayloadLength);

//   // 4. Build Header (unprotected)
//   QuicHeaderInfo headerInfo = buildQuicHeader(
//     packetType,
//     dcid,
//     scid,
//     token,
//     lengthField,
//     pnLength,
//   );
//   Uint8List header = headerInfo.header;
//   int packetNumberOffset = headerInfo.packetNumberOffset;

//   // 5. Check and apply padding if needed (Long Headers only)
//   if (packetType != '1rtt') {
//     // The Header Protection sample starts at PN offset + 4 and must be 16 bytes.
//     const minSampleLength = 16;

//     // The total packet length must be >= (PN offset + 4 + 16).
//     final minTotalLength = packetNumberOffset + 4 + minSampleLength;
//     final fullLength = header.length + pnLength + encodedFrames.length + 16;

//     if (fullLength < minTotalLength) {
//       // Required Protected Bytes = minTotalLength - (Header Length + PN Length)
//       final requiredProtectedDataLength =
//           minTotalLength - (header.length + pnLength);

//       // Since the tag is 16 bytes, the frame content must be:
//       final requiredFramesLength = requiredProtectedDataLength - 16;

//       if (requiredFramesLength > encodedFrames.length) {
//         final extraPadding = requiredFramesLength - encodedFrames.length;

//         // Add padding (zero bytes) to encodedFrames
//         final padded = Uint8List(encodedFrames.length + extraPadding);
//         padded.setAll(0, encodedFrames);
//         encodedFrames = padded;

//         // RECALCULATE LENGTH FIELD AND REBUILD HEADER
//         unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
//         lengthField = writeVarInt(unprotectedPayloadLength);
//         headerInfo = buildQuicHeader(
//           packetType,
//           dcid,
//           scid,
//           token,
//           lengthField,
//           pnLength,
//         );
//         header = headerInfo.header;
//         packetNumberOffset = headerInfo.packetNumberOffset;
//       }
//     }
//   }

//   // 6. Build AAD: Unprotected Header + Unprotected Packet Number
//   final fullHeader = concatUint8Lists([header, packetNumberField]);

//   // 7. Encrypt Payload
//   final ciphertext = aeadEncrypt(
//     writeKey,
//     writeIv,
//     packetNumber,
//     encodedFrames,
//     fullHeader,
//   );
//   if (ciphertext == null) return null;

//   // 8. Build Full Packet (before Header Protection)
//   final fullPacket = concatUint8Lists([header, packetNumberField, ciphertext]);

//   // 9. Apply Header Protection
//   return applyHeaderProtection(
//     fullPacket,
//     packetNumberOffset,
//     writeHp,
//     pnLength,
//   );
// }

/// Encrypts a QUIC packet and applies Header Protection.
///
/// Combines the logic from `encrypt_quic_packet` and `encrypt_quic_packet2`
/// with correct padding logic for AES-GCM (16-byte sample).
Uint8List? encryptQuicPacket(
  String packetType,
  Uint8List encodedFrames,
  Uint8List writeKey,
  Uint8List writeIv,
  Uint8List writeHp,
  int packetNumber,
  Uint8List dcid,
  Uint8List scid,
  Uint8List? token, {
  bool logDebug = true,
}) {
  // ✅ Log keys used for decrypt

  if (logDebug) {
    print("--- encryptQuicPacket keys ---");
    print('READ.key = ${HEX.encode(writeKey)}');
    print('READ.iv  = ${HEX.encode(writeIv)}');
    print('READ.hp  = ${HEX.encode(writeHp)}');
    print('dcid     = ${HEX.encode(dcid)}');
    print("dcid     = ${HEX.encode(dcid)}");
    print('pkt[0]   = 0x${encodedFrames[0].toRadixString(16).padLeft(2, '0')}');
    print('pkt.len  = ${encodedFrames.length}');
  }

  // 1. Determine Packet Number Length
  int pnLength;
  if (packetNumber <= 0xff) {
    pnLength = 1;
  } else if (packetNumber <= 0xffff)
    pnLength = 2;
  else if (packetNumber <= 0xffffff)
    pnLength = 3;
  else
    pnLength = 4;

  // 2. Truncate Packet Number field to pnLength bytes (Big Endian)
  final pnFull = ByteData(4);
  pnFull.setUint32(0, packetNumber, Endian.big);
  final packetNumberField = pnFull.buffer.asUint8List().sublist(4 - pnLength);

  // 3. Initial calculation of protected length (PN field + frames + 16 byte GCM tag)
  int protectedPayloadLength = encodedFrames.length + pnLength + 16;
  Uint8List lengthField = writeVarInt(protectedPayloadLength);

  // 4. Build Header (unprotected)
  QuicHeaderInfo headerInfo = buildQuicHeader(
    packetType,
    dcid,
    scid,
    token,
    lengthField,
    pnLength,
  );
  Uint8List header = headerInfo.header;
  int packetNumberOffset = headerInfo.packetNumberOffset;

  // 5. Check and apply padding if needed (Long Headers only)
  // This ensures the packet is long enough for the Header Protection sample.
  if (packetType != '1rtt') {
    // The HP sample starts immediately after the PN field and must be 16 bytes.
    const minSampleLength = 16;

    // Minimum total packet length required = (PN offset + PN length + 16)
    final minTotalLength = packetNumberOffset + pnLength + minSampleLength;

    // Current total length = Header + PN Field + Frames + 16-byte Tag
    final fullLength = header.length + pnLength + encodedFrames.length + 16;

    if (fullLength < minTotalLength) {
      // Calculate the required length for the Ciphertext + Tag part:
      // Required Protected Data Length (PN + Ciphertext + Tag) = minTotalLength - Header Length
      final requiredProtectedDataLength = minTotalLength - header.length;

      // Required (Ciphertext + Tag) length = Required Protected Data Length - PN Length
      final requiredCiphertextTagLength =
          requiredProtectedDataLength - pnLength;

      // Required Frames Length = Required (Ciphertext + Tag) length - Tag Length (16)
      final requiredFramesLength = requiredCiphertextTagLength - 16;

      if (requiredFramesLength > encodedFrames.length) {
        final extraPadding = requiredFramesLength - encodedFrames.length;

        // Add padding (zero bytes) to encodedFrames
        final padded = Uint8List(encodedFrames.length + extraPadding);
        padded.setAll(0, encodedFrames);
        encodedFrames = padded;

        // RECALCULATE LENGTH FIELD AND REBUILD HEADER
        // The L field value must now encode the padded length.
        protectedPayloadLength = encodedFrames.length + pnLength + 16;
        lengthField = writeVarInt(protectedPayloadLength);

        // Rebuild header to update the Length field VarInt (L)
        headerInfo = buildQuicHeader(
          packetType,
          dcid,
          scid,
          token,
          lengthField,
          pnLength,
        );
        header = headerInfo.header;
        packetNumberOffset = headerInfo.packetNumberOffset;
      }
    }
  }

  // 6. Build AAD: Unprotected Header + Unprotected Packet Number
  final fullHeader = concatUint8Lists([header, packetNumberField]);

  // 7. Encrypt Payload
  // The plaintext is the encoded frames (possibly padded).
  // The output 'ciphertext' includes the 16-byte tag.
  final ciphertext = aeadEncrypt(
    writeKey,
    writeIv,
    packetNumber,
    encodedFrames,
    fullHeader,
  );
  if (ciphertext == null) return null;

  // 8. Build Full Packet (before Header Protection)
  final fullPacket = concatUint8Lists([header, packetNumberField, ciphertext]);

  // 9. Apply Header Protection
  return applyHeaderProtection(
    fullPacket,
    packetNumberOffset,
    writeHp,
    pnLength,
  );
}
//
// main function with corrected DCID and SCID inputs:

// void main() {
//   final readKey = Uint8List.fromList(
//     HEX.decode("b14b918124fda5c8d79847602fa3520b"),
//   );
//   final readIv = Uint8List.fromList(HEX.decode("ddbc15dea80925a55686a7df"));

//   final readHp = Uint8List.fromList(
//     HEX.decode("6df4e9d737cdf714711d7c617ee82981"),
//   );

//   // FIX: DCID is 8 bytes, matching the Expected packet's header (0x08 length field).
//   // The first byte of the original input array (0x08) was likely a mistake in the definition.
//   final dcid = Uint8List.fromList([
//     0x00, // Starts at 0x00 to match Expected hex: ...08(DCID Len) 0001020304050607
//     0x01,
//     0x02,
//     0x03,
//     0x04,
//     0x05,
//     0x06,
//     0x07,
//   ]);

//   final largestPn = 0;

//   decryptQuicPacket(
//     quickPacket,
//     readKey,
//     readIv,
//     readHp,
//     dcid, // Required for Short Header parsing
//     largestPn, // Largest packet number received so far
//   );

//   // FIX: SCID is 5 bytes, matching the Expected packet's header (0x05 length field).
//   final scid = Uint8List.fromList([
//     0x63, // Starts at 0x63 to match Expected hex: ...05(SCID Len) 635f636964
//     0x5f,
//     0x63,
//     0x69,
//     0x64,
//   ]);

//   // Assuming `decryptedBytes` is correctly set after decryption and holds 242 bytes of payload.
//   final encrypted = encryptQuicPacket(
//     "initial",
//     decryptedBytes,
//     readKey,
//     readIv,
//     readHp,
//     0,
//     dcid,
//     scid,
//     null,
//   );
//   print("Get encrypted packet: ${HEX.encode(encrypted!)}");

//   print("Expected:             ${HEX.encode(quickPacket)}");

//   final ver = Version.version1;

//   // final cid = dcid;
//   // final (clientSealer, clientOpener) = newInitialAEAD(
//   //   cid,
//   //   Perspective.client,
//   //   ver,
//   // );

//   // final (serverSealer, serverOpener) = newInitialAEAD(
//   //   cid,
//   //   Perspective.server,
//   //   ver,
//   // );
//   // print("Client sealer");
//   // print("Write Key: ${clientSealer.aead.key}");
//   // print("Expected   $readKey");
//   // print("");

//   // print("Write IV: ${clientSealer.aead.nonceMask}");
//   // print("Expected  $readIv");
//   // print("");

//   // print("Header Protection Key: ${clientSealer.hp}");
//   // print("Expected               $readHp");
//   // print("");

//   // print("Server opener");
//   // print("Write Key: ${serverOpener.aead.key}");
//   // print("Expected   $readKey");
//   // print("");

//   // print("Write IV: ${serverOpener.aead.nonceMask}");
//   // print("Expected  $readIv");
//   // print("");

//   // print("Header Protection Key: ${serverOpener.hp}");
//   // print("Expected               $readHp");
//   // print("");
// }

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

final decryptedBytes = Uint8List.fromList([
  0x06,
  0x00,
  0x40,
  0xee,
  0x01,
  0x00,
  0x00,
  0xea,
  0x03,
  0x03,
  0x00,
  0x01,
  0x02,
  0x03,
  0x04,
  0x05,
  0x06,
  0x07,
  0x08,
  0x09,
  0x0a,
  0x0b,
  0x0c,
  0x0d,
  0x0e,
  0x0f,
  0x10,
  0x11,
  0x12,
  0x13,
  0x14,
  0x15,
  0x16,
  0x17,
  0x18,
  0x19,
  0x1a,
  0x1b,
  0x1c,
  0x1d,
  0x1e,
  0x1f,
  0x00,
  0x00,
  0x06,
  0x13,
  0x01,
  0x13,
  0x02,
  0x13,
  0x03,
  0x01,
  0x00,
  0x00,
  0xbb,
  0x00,
  0x00,
  0x00,
  0x18,
  0x00,
  0x16,
  0x00,
  0x00,
  0x13,
  0x65,
  0x78,
  0x61,
  0x6d,
  0x70,
  0x6c,
  0x65,
  0x2e,
  0x75,
  0x6c,
  0x66,
  0x68,
  0x65,
  0x69,
  0x6d,
  0x2e,
  0x6e,
  0x65,
  0x74,
  0x00,
  0x0a,
  0x00,
  0x08,
  0x00,
  0x06,
  0x00,
  0x1d,
  0x00,
  0x17,
  0x00,
  0x18,
  0x00,
  0x10,
  0x00,
  0x0b,
  0x00,
  0x09,
  0x08,
  0x70,
  0x69,
  0x6e,
  0x67,
  0x2f,
  0x31,
  0x2e,
  0x30,
  0x00,
  0x0d,
  0x00,
  0x14,
  0x00,
  0x12,
  0x04,
  0x03,
  0x08,
  0x04,
  0x04,
  0x01,
  0x05,
  0x03,
  0x08,
  0x05,
  0x05,
  0x01,
  0x08,
  0x06,
  0x06,
  0x01,
  0x02,
  0x01,
  0x00,
  0x33,
  0x00,
  0x26,
  0x00,
  0x24,
  0x00,
  0x1d,
  0x00,
  0x20,
  0x35,
  0x80,
  0x72,
  0xd6,
  0x36,
  0x58,
  0x80,
  0xd1,
  0xae,
  0xea,
  0x32,
  0x9a,
  0xdf,
  0x91,
  0x21,
  0x38,
  0x38,
  0x51,
  0xed,
  0x21,
  0xa2,
  0x8e,
  0x3b,
  0x75,
  0xe9,
  0x65,
  0xd0,
  0xd2,
  0xcd,
  0x16,
  0x62,
  0x54,
  0x00,
  0x2d,
  0x00,
  0x02,
  0x01,
  0x01,
  0x00,
  0x2b,
  0x00,
  0x03,
  0x02,
  0x03,
  0x04,
  0x00,
  0x39,
  0x00,
  0x31,
  0x03,
  0x04,
  0x80,
  0x00,
  0xff,
  0xf7,
  0x04,
  0x04,
  0x80,
  0xa0,
  0x00,
  0x00,
  0x05,
  0x04,
  0x80,
  0x10,
  0x00,
  0x00,
  0x06,
  0x04,
  0x80,
  0x10,
  0x00,
  0x00,
  0x07,
  0x04,
  0x80,
  0x10,
  0x00,
  0x00,
  0x08,
  0x01,
  0x0a,
  0x09,
  0x01,
  0x0a,
  0x0a,
  0x01,
  0x03,
  0x0b,
  0x01,
  0x19,
  0x0f,
  0x05,
  0x63,
  0x5f,
  0x63,
  0x69,
  0x64,
]);
