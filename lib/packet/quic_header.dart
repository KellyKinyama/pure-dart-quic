import 'dart:typed_data';

import '../utils.dart';

// import 'utils.dart';
// enum QuicPacketType{
//   isInitial
// }

/// Encodes a 32-bit integer QUIC version into a 4-byte Big Endian [Uint8List].
Uint8List encodeVersion(int version) {
  final result = Uint8List(4);
  final view = ByteData.view(result.buffer);
  view.setUint32(0, version, Endian.big);
  return result;
}

// Result class for Header building
class QuicHeaderInfo {
  final Uint8List header;
  final int packetNumberOffset;
  QuicHeaderInfo({required this.header, required this.packetNumberOffset});
}

/// Constructs the unprotected QUIC header up to the Packet Number field.
QuicHeaderInfo buildQuicHeader(
  String packetType,
  Uint8List dcid,
  Uint8List scid,
  Uint8List? token,
  Uint8List lengthField, // VarInt for protected payload length
  int pnLen, // 1, 2, 3, or 4
) {
  final List<Uint8List> hdrParts = [];
  int firstByte;

  // pnLen - 1 corresponds to the two low bits (LL) of the first byte
  final pnLenBits = (pnLen - 1) & 0x03;

  // Step 1: Define the first byte based on packet type
  if (packetType == 'initial') {
    firstByte = 0xC0 | pnLenBits; // 1100_00LL
  } else if (packetType == 'handshake') {
    firstByte = 0xE0 | pnLenBits; // 1110_00LL
  } else if (packetType == '0rtt') {
    firstByte = 0xD0 | pnLenBits; // 1101_00LL
  } else if (packetType == '1rtt' || packetType == 'short') {
    // Short Header: 01xx_xxLL. The bits 4 and 5 are reserved (0) or Key Phase (1).
    firstByte = 0x40 | pnLenBits; // 0100_00LL (Assuming Key Phase 0)

    // Short Header is: Type (1 byte) + DCID + Packet Number
    hdrParts.add(Uint8List.fromList([firstByte]));
    hdrParts.add(dcid);

    final header = concatUint8Lists(hdrParts);
    return QuicHeaderInfo(
      header: header,
      packetNumberOffset: header.length, // PN starts immediately after DCID
    );
  } else {
    throw Exception('Unsupported packet type: $packetType');
  }

  // Steps 2-4: Long Header construction
  hdrParts.add(Uint8List.fromList([firstByte]));
  hdrParts.add(encodeVersion(0x00000001)); // QUIC v1

  // DCID Length + Value
  hdrParts.add(writeVarInt(dcid.length));
  hdrParts.add(dcid);

  // SCID Length + Value
  hdrParts.add(writeVarInt(scid.length));
  hdrParts.add(scid);

  // Step 3: Token for Initial packets
  if (packetType == 'initial') {
    final effectiveToken = token ?? Uint8List(0);
    hdrParts.add(writeVarInt(effectiveToken.length));
    hdrParts.add(effectiveToken);
  }

  // Step 4: Length field (Payload Length, VarInt)
  hdrParts.add(lengthField);

  // Step 5: Calculate PN offset
  final header = concatUint8Lists(hdrParts);
  return QuicHeaderInfo(
    header: header,
    packetNumberOffset:
        header.length, // PN starts immediately after the Length field
  );
}
