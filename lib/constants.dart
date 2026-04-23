//===========
// HTTP/3 + WebTransport constants / state
// ============================================================

import 'dart:math' as math;
import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'package:x25519/x25519.dart' as ecdhe;

import '../utils.dart';
import 'frames/quic_frames.dart';
import 'handshake/tls_msg.dart';

const int H3_FRAME_DATA = 0x00;
const int H3_FRAME_HEADERS = 0x01;
const int H3_FRAME_SETTINGS = 0x04;

const int H3_STREAM_TYPE_CONTROL = 0x00;

const String WT_PROTOCOL = 'webtransport';

// const int H3_FRAME_DATA = 0x00;
// const int H3_FRAME_HEADERS = 0x01;
// const int H3_FRAME_SETTINGS = 0x04;

// const int H3_STREAM_TYPE_CONTROL = 0x00;
const int H3_STREAM_TYPE_QPACK_ENCODER = 0x02;
const int H3_STREAM_TYPE_QPACK_DECODER = 0x03;

// WebTransport unidirectional stream type
const int WT_STREAM_TYPE_UNI = 0x54;

// const String WT_PROTOCOL = 'webtransport';

class Http3State {
  // ----------------------------------------------------------
  // Existing behavior (kept exactly so current server keeps working)
  // ----------------------------------------------------------
  bool controlStreamSent = false;

  // Reassembly buffers per QUIC stream (raw QUIC stream bytes)
  final Map<int, Map<int, Uint8List>> streamChunks =
      <int, Map<int, Uint8List>>{};

  // Current read offset per QUIC stream
  final Map<int, int> streamReadOffsets = <int, int>{};

  // WebTransport sessions keyed by CONNECT stream id
  final Map<int, WebTransportSession> webTransportSessions =
      <int, WebTransportSession>{};

  // ----------------------------------------------------------
  // New fields (additive only; safe for current server)
  // ----------------------------------------------------------

  /// Whether we have seen the peer's HTTP/3 control stream.
  /// Useful if you later want to require client SETTINGS before
  /// accepting CONNECT / WebTransport.
  bool peerControlStreamSeen = false;

  /// Stream classification:
  ///   request
  ///   client_control
  ///   qpack_encoder
  ///   qpack_decoder
  ///   wt_uni
  ///   other_client_uni
  ///   other
  final Map<int, String> streamKinds = <int, String>{};

  /// For client/server uni streams, this stores the length of the
  /// stream-type prefix varint so we can strip it before parsing
  /// HTTP/3 frames or WT payloads.
  final Map<int, int> streamTypePrefixLen = <int, int>{};

  /// HTTP/3 frame reassembly buffers after removing uni-stream type prefixes.
  /// This lets you parse H3 frames independently from the raw QUIC stream.
  final Map<int, Map<int, Uint8List>> h3FrameChunks =
      <int, Map<int, Uint8List>>{};

  /// Read offsets for the H3-frame view of each stream.
  final Map<int, int> h3FrameReadOffsets = <int, int>{};

  /// For WebTransport unidirectional streams, remember which
  /// CONNECT/session id a given QUIC stream belongs to.
  final Map<int, int> wtUniSessionIdByStream = <int, int>{};
}

class WebTransportSession {
  final int connectStreamId;
  final Set<int> streams = <int>{};

  WebTransportSession(this.connectStreamId);
}

enum EncryptionLevel { initial, handshake, application }

class QuicKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  const QuicKeys({required this.key, required this.iv, required this.hp});

  @override
  String toString() {
    return """QuicKeys{
  key: ${HEX.encode(key)};
  iv:  ${HEX.encode(iv)};
  hp:  ${HEX.encode(hp)};
}""";
  }
}

class KeyPair {
  final Uint8List _privateKey;

  KeyPair._(this._privateKey);

  /// Raw 32-byte X25519 public key.
  /// Raw 32-byte X25519 public key.
  Uint8List get publicKeyBytes {
    // Public key = X25519(privateKey, basePoint)
    final pub = ecdhe.X25519(_privateKey, ecdhe.basePoint);
    return Uint8List.fromList(pub);
  }

  /// Raw 32-byte X25519 private key.
  Uint8List get privateKeyBytes => Uint8List.fromList(_privateKey);

  static KeyPair generate() {
    final seed = Uint8List(32);
    final rnd = math.Random.secure();
    for (var i = 0; i < seed.length; i++) {
      seed[i] = rnd.nextInt(256);
    }
    return KeyPair._(seed);
  }
}

class PacketNumberSpace {
  int largestPn = -1;

  void onPacketDecrypted(int pn) {
    if (pn > largestPn) {
      largestPn = pn;
    }
  }
}

class AckState {
  final Set<int> received = <int>{};
  int nextPn = 0;

  int allocatePn() => nextPn++;
}

List<Uint8List> splitCoalescedPackets(Uint8List buf) {
  final out = <Uint8List>[];
  int i = 0;

  while (i < buf.length) {
    // Need at least 5 bytes for long header
    if (i + 5 > buf.length) break;

    final flags = buf[i];
    final isLong = (flags & 0x80) != 0;

    if (isLong) {
      int p = i + 1;

      // ---- Version (4 bytes) ----
      if (p + 4 > buf.length) break;
      p += 4;

      // ---- DCID ----
      if (p >= buf.length) break;
      final dcidLen = buf[p++];
      if (p + dcidLen > buf.length) break;
      p += dcidLen;

      // ---- SCID ----
      if (p >= buf.length) break;
      final scidLen = buf[p++];
      if (p + scidLen > buf.length) break;
      p += scidLen;

      // ---- Token Length (ONLY Initial packets) ----
      final packetType = (flags >> 4) & 0x03;

      if (packetType == 0x00) {
        // Initial packet → token field present
        final token = readVarInt(buf, p);
        if (token == null) break;

        p += token.byteLength;

        if (p + token.value > buf.length) break;
        p += token.value;
      }

      // ---- Length field (varint) ----
      final lengthField = readVarInt(buf, p);
      if (lengthField == null) break;

      final payloadLen = lengthField.value;
      p += lengthField.byteLength;

      // ---- Bounds check to avoid RangeError ----
      final pktEnd = p + payloadLen;
      if (pktEnd > buf.length) {
        throw RangeError(
          "QUIC long header claims payload length $payloadLen but only "
          "${buf.length - p} bytes remain",
        );
      }

      // ---- Extract packet ----
      out.add(buf.sublist(i, pktEnd));

      // Move to next packet
      i = pktEnd;
      continue;
    }

    // ------------------------------
    // Short header → runs to end of UDP datagram
    // ------------------------------
    out.add(buf.sublist(i));
    break;
  }

  return out;
}

enum LongPacketType { initial, zeroRtt, handshake, retry }

LongPacketType parseLongHeaderType(Uint8List packet) {
  final firstByte = packet[0];

  // Bits 4–5 encode the long header packet type
  final typeBits = (firstByte >> 4) & 0x03;

  switch (typeBits) {
    case 0x0:
      return LongPacketType.initial;
    case 0x1:
      return LongPacketType.zeroRtt;
    case 0x2:
      return LongPacketType.handshake;
    case 0x3:
      return LongPacketType.retry;
    default:
      throw StateError('Invalid long header type bits: $typeBits');
  }
}

Uint8List padTo1200(Uint8List pkt) {
  const minInitialSize = 1200;
  if (pkt.length >= minInitialSize) return pkt;
  final out = Uint8List(minInitialSize);
  out.setRange(0, pkt.length, pkt);
  return out;
}

/// =============================================================
/// Parsed QUIC payload result
/// =============================================================
class ParsedQuicPayload {
  final List<QuicFrame> frames;
  final List<CryptoFrame> cryptoFrames;
  final AckFrame? ack;
  final List<TlsHandshakeMessage> tlsMessages;

  ParsedQuicPayload({
    required this.frames,
    required this.cryptoFrames,
    this.ack,
    required this.tlsMessages,
  });

  @override
  String toString() {
    return 'ParsedQuicPayload('
        'frames=${frames.length}, '
        'cryptoFrames=${cryptoFrames.length}, '
        'tlsMessages=${tlsMessages.length}, '
        'ack=${ack != null}'
        ')';
  }
}
