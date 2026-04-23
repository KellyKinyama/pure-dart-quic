import 'dart:math' as math;
import 'dart:typed_data';

import '../buffer.dart';
import '../handshake/client_hello.dart';
import '../handshake/tls_msg.dart';

/// ------------------------------------------------------------
/// QUIC transport parameter IDs ( 0x0004;/// QUIC transport parameter IDs (RFC 9000)
const int tpInitialMaxStreamDataBidiLocal = 0x0005;
const int tpInitialMaxStreamDataBidiRemote = 0x0006;
const int tpInitialMaxStreamDataUni = 0x0007;
const int tpInitialMaxStreamsBidi = 0x0008;
const int tpInitialMaxStreamsUni = 0x0009;
const int tpActiveConnectionIdLimit = 0x000e;
const int tpInitialSourceConnectionId = 0x000f;

/// ------------------------------------------------------------
/// QUIC varint encoder
/// ------------------------------------------------------------
Uint8List _encodeVarInt(int v) {
  if (v < 0) {
    throw ArgumentError('QUIC varint must be non-negative: $v');
  }

  if (v < 0x40) {
    // 1-byte encoding: 00xxxxxx
    return Uint8List.fromList([v & 0x3f]);
  } else if (v < 0x4000) {
    // 2-byte encoding: 01xxxxxx xxxxxxxx
    return Uint8List.fromList([0x40 | ((v >> 8) & 0x3f), v & 0xff]);
  } else if (v < 0x40000000) {
    // 4-byte encoding: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    return Uint8List.fromList([
      0x80 | ((v >> 24) & 0x3f),
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    ]);
  } else if (v < 0x4000000000000000) {
    // 8-byte encoding: 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    //                  xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    return Uint8List.fromList([
      0xC0 | ((v >> 56) & 0x3f),
      (v >> 48) & 0xff,
      (v >> 40) & 0xff,
      (v >> 32) & 0xff,
      (v >> 24) & 0xff,
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    ]);
  } else {
    throw ArgumentError('QUIC varint out of range: $v');
  }
}

/// ------------------------------------------------------------
/// Transport parameter helpers
/// ------------------------------------------------------------

/// Integer-valued transport parameter:
///   id(varint) || length(varint) || value(varint)
Uint8List _tpInt(int id, int value) {
  final encodedValue = _encodeVarInt(value);

  return Uint8List.fromList([
    ..._encodeVarInt(id),
    ..._encodeVarInt(encodedValue.length),
    ...encodedValue,
  ]);
}

/// Byte-string transport parameter:
///   id(varint) || length(varint) || raw bytes
Uint8List _tpBytes(int id, Uint8List value) {
  return Uint8List.fromList([
    ..._encodeVarInt(id),
    ..._encodeVarInt(value.length),
    ...value,
  ]);
}

/// ------------------------------------------------------------
/// Build a dynamic TLS 1.3 ClientHello for QUIC / HTTP/3
///
/// IMPORTANT:
/// - pass the X25519 *public* key here, not the private key
/// - use `serialize()` on the returned ClientHello to get the
///   full TLS Handshake message (header + body)
/// ------------------------------------------------------------
ClientHello buildInitialClientHello({
  required String hostname,
  required Uint8List x25519PublicKey,
  required Uint8List localCid,
  List<String> alpns = const ['h3'],
}) {
  final rnd = math.Random.secure();
  final random = Uint8List.fromList(List.generate(32, (_) => rnd.nextInt(256)));

  final extensions = <TlsExtension>[];

  TlsExtension makeExt(int type, QuicBuffer buf) {
    final bytes = buf.toBytes();
    return TlsExtension(type: type, length: bytes.length, data: bytes);
  }

  // ----------------------------------------------------------
  // 1) SNI
  // ----------------------------------------------------------
  final hostBytes = Uint8List.fromList(hostname.codeUnits);
  final sniBuf = QuicBuffer()
    ..pushUint16(hostBytes.length + 3) // server_name_list length
    ..pushUint8(0x00) // host_name
    ..pushUint16(hostBytes.length)
    ..pushBytes(hostBytes);

  extensions.add(makeExt(0x0000, sniBuf));

  // ----------------------------------------------------------
  // 2) Supported groups
  // ----------------------------------------------------------
  final groupsBuf = QuicBuffer()
    ..pushUint16(6)
    ..pushUint16(0x001d) // x25519
    ..pushUint16(0x0017) // secp256r1
    ..pushUint16(0x0018); // secp384r1

  extensions.add(makeExt(0x000a, groupsBuf));

  // ----------------------------------------------------------
  // 3) Signature algorithms
  // ----------------------------------------------------------
  final sigBuf = QuicBuffer()
    ..pushUint16(4)
    ..pushUint16(0x0403) // ecdsa_secp256r1_sha256
    ..pushUint16(0x0804); // rsa_pss_rsae_sha256

  extensions.add(makeExt(0x000d, sigBuf));

  // ----------------------------------------------------------
  // 4) KeyShare (X25519)
  // ----------------------------------------------------------
  final keyShareEntry = QuicBuffer()
    ..pushUint16(0x001d) // x25519
    ..pushUint16(x25519PublicKey.length)
    ..pushBytes(x25519PublicKey);

  final keyShareBuf = QuicBuffer()
    ..pushUint16(keyShareEntry.writeIndex)
    ..pushBytes(keyShareEntry.toBytes());

  extensions.add(makeExt(0x0033, keyShareBuf));

  // ----------------------------------------------------------
  // 5) PSK key exchange modes
  // ----------------------------------------------------------
  final pskBuf = QuicBuffer()
    ..pushUint8(1)
    ..pushUint8(1); // psk_dhe_ke

  extensions.add(makeExt(0x002d, pskBuf));

  // ----------------------------------------------------------
  // 6) Supported versions = TLS 1.3
  // ----------------------------------------------------------
  final versionsBuf = QuicBuffer()
    ..pushUint8(2)
    ..pushUint8(0x03)
    ..pushUint8(0x04);

  extensions.add(makeExt(0x002b, versionsBuf));

  // ----------------------------------------------------------
  // 7) QUIC transport parameters
  //
  // NOTE:
  // integer-valued transport params MUST be encoded as QUIC varints
  // inside the parameter value bytes.
  // ----------------------------------------------------------
  final tpBytes = BytesBuilder()
    ..add(_tpInt(tpMaxIdleTimeout, 30000))
    ..add(_tpInt(tpMaxUdpPayloadSize, 65527))
    ..add(_tpInt(tpInitialMaxData, 1 << 20))
    ..add(_tpInt(tpInitialMaxStreamDataBidiLocal, 1 << 18))
    ..add(_tpInt(tpInitialMaxStreamDataBidiRemote, 1 << 18))
    ..add(_tpInt(tpInitialMaxStreamDataUni, 1 << 18))
    ..add(_tpInt(tpInitialMaxStreamsBidi, 16))
    ..add(_tpInt(tpInitialMaxStreamsUni, 16))
    ..add(_tpInt(tpActiveConnectionIdLimit, 4))
    ..add(_tpBytes(tpInitialSourceConnectionId, localCid));

  extensions.add(
    TlsExtension(
      type: 0x0039,
      length: tpBytes.toBytes().length,
      data: tpBytes.toBytes(),
    ),
  );

  // ----------------------------------------------------------
  // IMPORTANT:
  // We set `alpn: alpns` here so that ClientHello.serialize()
  // will upsert the ALPN extension correctly.
  //
  // We intentionally do NOT manually add extension 0x0010 here,
  // because serialize() / upsertAlpnExtension() will handle it
  // from the semantic `alpn` field.
  // ----------------------------------------------------------
  return ClientHello(
    type: 'client_hello',
    legacyVersion: 0x0303,
    random: random,
    sessionId: Uint8List(0),
    cipherSuites: const [
      0x1301, // TLS_AES_128_GCM_SHA256
      0x1302, // TLS_AES_256_GCM_SHA384
      0x1303, // TLS_CHACHA20_POLY1305_SHA256
    ],
    compressionMethods: Uint8List.fromList([0x00]),
    extensions: extensions,
    rawData: Uint8List(0),
    alpn: alpns,
  );
}

/// ------------------------------------------------------------
const int tpMaxIdleTimeout = 0x0001;
const int tpMaxUdpPayloadSize = 0x0003;
const int tpInitialMaxData = 0x0004;
