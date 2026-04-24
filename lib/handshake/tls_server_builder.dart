// =============================================================
// tls_server_handshake.dart

// =============================================================

import 'dart:convert';
// import 'dart:math' as math;
import 'dart:typed_data';

// import 'package:hex/hex.dart';
import 'package:crypto/crypto.dart' as crypto;

import '../cipher/ecdsa.dart';
import '../cipher/cert_utils.dart';
import '../cipher/fingerprint.dart';
import '../cipher/hash.dart';
import 'server_hello.dart';
// import '../hash.dart';
// import '../hkdf.dart';
// import '../cipher/x25519.dart';
// import '../quic_learn/cert_utils.dart';
// import '../quic_learn/server/quic_server_session.dart';

// =============================================================
// Constants
// =============================================================

const int tlsAes128GcmSha256 = 0x1301;
const int x25519Group = 0x001d;

// TLS 1.3 signature algorithm
// ecdsa_secp256r1_sha256
const int ecdsaP256Sha256 = 0x0403;

// QUIC transport parameter IDs (RFC 9000)
const int tpInitialMaxData = 0x0004;
const int tpInitialMaxStreamDataBidiLocal = 0x0005;
const int tpInitialMaxStreamDataBidiRemote = 0x0006;
const int tpInitialMaxStreamsBidi = 0x0008;
const int tpIdleTimeout = 0x0001;
// QUIC transport parameter IDs (RFC 9000)
const int tpOriginalDestinationConnectionId = 0x0000;
// const int tpIdleTimeout = 0x0001;
const int tpMaxUdpPayloadSize = 0x0003;
// const int tpInitialMaxData = 0x0004;
// const int tpInitialMaxStreamDataBidiLocal = 0x0005;
// const int tpInitialMaxStreamDataBidiRemote = 0x0006;
const int tpInitialMaxStreamDataUni = 0x0007;
// const int tpInitialMaxStreamsBidi = 0x0008;
const int tpInitialMaxStreamsUni = 0x0009;
const int tpActiveConnectionIdLimit = 0x000e;
const int tpInitialSourceConnectionId = 0x000f;
// =============================================================
// Helper types
// =============================================================

// =============================================================
// ALPN
// =============================================================

// =============================================================
// ALPN
// =============================================================

const String alpnQuicEchoExample = 'quic-echo-example';
const String alpnH3 = 'h3';
const String alpnH3_32 = 'h3-32';
const String alpnH3_29 = 'h3-29';
const String alpnPing = 'ping/1.0';

/// Server preference order.
/// The first match with the client's offered ALPNs wins.
const List<String> supportedAlpnProtocols = [
  alpnH3,
  alpnH3_32,
  alpnH3_29,
  alpnQuicEchoExample,
  alpnPing,
];

String chooseServerAlpn(List<String> clientOffered) {
  for (final supported in supportedAlpnProtocols) {
    if (clientOffered.contains(supported)) {
      return supported;
    }
  }

  throw StateError(
    'No compatible ALPN. Client offered: $clientOffered, '
    'server supports: $supportedAlpnProtocols',
  );
}

class BuiltExtension {
  final int type;
  final Uint8List data;
  const BuiltExtension({required this.type, required this.data});
}

class CertificateEntry {
  final Uint8List cert;
  final Uint8List extensions;
  CertificateEntry({required this.cert, Uint8List? extensions})
    : extensions = extensions ?? Uint8List(0);
}

class ServerHandshakeArtifacts {
  final Uint8List serverHello;
  final Uint8List encryptedExtensions;
  final Uint8List certificate;
  final Uint8List certificateVerify;

  const ServerHandshakeArtifacts({
    required this.serverHello,
    required this.encryptedExtensions,
    required this.certificate,
    required this.certificateVerify,
  });
}

// =============================================================
// QUIC Transport Parameters (MANDATORY)
// =============================================================

Uint8List _encodeVarInt(int v) {
  // QUIC varint encoding (RFC 9000)
  // 1 byte:  0..63
  // 2 bytes: 64..16383
  // 4 bytes: 16384..1073741823
  // 8 bytes: 1073741824..(2^62-1)
  if (v < 0x40) {
    // 00
    return Uint8List.fromList([v & 0x3f]);
  } else if (v < 0x4000) {
    // 01
    return Uint8List.fromList([0x40 | ((v >> 8) & 0x3f), v & 0xff]);
  } else if (v < 0x40000000) {
    // 10
    return Uint8List.fromList([
      0x80 | ((v >> 24) & 0x3f),
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    ]);
  } else if (v < 0x4000000000000000) {
    // 11
    final b = ByteData(8);
    b.setUint8(0, 0xC0 | ((v >> 56) & 0x3f));
    b.setUint8(1, (v >> 48) & 0xff);
    b.setUint8(2, (v >> 40) & 0xff);
    b.setUint8(3, (v >> 32) & 0xff);
    b.setUint8(4, (v >> 24) & 0xff);
    b.setUint8(5, (v >> 16) & 0xff);
    b.setUint8(6, (v >> 8) & 0xff);
    b.setUint8(7, v & 0xff);
    return b.buffer.asUint8List();
  } else {
    throw ArgumentError('varint out of range: $v');
  }
}

Uint8List _tp(int id, int value) {
  final v = _encodeVarInt(value);
  return Uint8List.fromList([
    ..._encodeVarInt(id),
    ..._encodeVarInt(v.length),
    ...v,
  ]);
}

Uint8List buildQuicTransportParameters({
  required Uint8List originalDestinationConnectionId,
  required Uint8List initialSourceConnectionId,
}) {
  return Uint8List.fromList([
    // ----------------------------------------------------------
    // Required / expected for a QUIC server
    // ----------------------------------------------------------
    ..._tpBytes(
      tpOriginalDestinationConnectionId,
      originalDestinationConnectionId,
    ),
    ..._tpBytes(tpInitialSourceConnectionId, initialSourceConnectionId),

    // ----------------------------------------------------------
    // Strongly recommended transport parameters
    // ----------------------------------------------------------
    ..._tp(tpActiveConnectionIdLimit, 4),
    ..._tp(tpIdleTimeout, 30),
    ..._tp(tpMaxUdpPayloadSize, 65527),

    // ----------------------------------------------------------
    // Flow control / stream limits
    // ----------------------------------------------------------
    ..._tp(tpInitialMaxData, 1 << 20),
    ..._tp(tpInitialMaxStreamDataBidiLocal, 1 << 18),
    ..._tp(tpInitialMaxStreamDataBidiRemote, 1 << 18),
    ..._tp(tpInitialMaxStreamDataUni, 1 << 18),
    ..._tp(tpInitialMaxStreamsBidi, 16),
    ..._tp(tpInitialMaxStreamsUni, 16),
  ]);
}

// =============================================================
// EncryptedExtensions
// =============================================================

// Uint8List buildAlpnExt(String protocol) {
//   final p = Uint8List.fromList(utf8.encode(protocol));
//   return Uint8List.fromList([0x00, p.length + 1, p.length, ...p]);
// }

Uint8List buildAlpnExt(String protocol) {
  final p = Uint8List.fromList(utf8.encode(protocol));

  // ALPN extension payload format:
  //   ProtocolNameList length (2 bytes)
  //   ProtocolName length (1 byte)
  //   ProtocolName bytes
  //
  // Since the server MUST select exactly one protocol,
  // ProtocolNameList contains exactly one entry.
  final listLen = 1 + p.length;

  return Uint8List.fromList([
    (listLen >> 8) & 0xff,
    listLen & 0xff,
    p.length,
    ...p,
  ]);
}

Uint8List buildEncryptedExtensions(List<BuiltExtension> extensions) {
  final ext = BytesBuilder();

  for (final e in extensions) {
    ext.add([
      (e.type >> 8) & 0xff,
      e.type & 0xff,
      (e.data.length >> 8) & 0xff,
      e.data.length & 0xff,
      ...e.data,
    ]);
  }

  final extBytes = ext.toBytes();
  final body = BytesBuilder()
    ..add([(extBytes.length >> 8) & 0xff, extBytes.length & 0xff])
    ..add(extBytes);

  final bodyBytes = body.toBytes();

  return Uint8List.fromList([
    0x08,
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
    ...bodyBytes,
  ]);
}

// =============================================================
// Certificate
// =============================================================

Uint8List buildCertificate(List<CertificateEntry> certificates) {
  final certList = BytesBuilder();
  print("Certificates: $certificates");

  for (final c in certificates) {
    certList.add([
      (c.cert.length >> 16) & 0xff,
      (c.cert.length >> 8) & 0xff,
      c.cert.length & 0xff,
      ...c.cert,
      (c.extensions.length >> 8) & 0xff,
      c.extensions.length & 0xff,
      ...c.extensions,
    ]);
  }

  final certBytes = certList.toBytes();
  final body = BytesBuilder()
    ..addByte(0x00)
    ..add([
      (certBytes.length >> 16) & 0xff,
      (certBytes.length >> 8) & 0xff,
      certBytes.length & 0xff,
    ])
    ..add(certBytes);

  final bodyBytes = body.toBytes();

  return Uint8List.fromList([
    0x0b,
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
    ...bodyBytes,
  ]);
}

Uint8List _extractFirstCertDerFromCertificateHandshake(Uint8List certMsg) {
  // certMsg format:
  // 0: handshake type (0x0b)
  // 1..3: body length
  // 4: cert_request_context length
  // 5..7: certificate_list length
  // 8..10: first cert length
  // 11.. : first cert DER

  if (certMsg.length < 11) {
    throw StateError('Certificate handshake message too short');
  }

  if (certMsg[0] != 0x0b) {
    throw StateError('Not a Certificate handshake message');
  }

  final contextLen = certMsg[4];
  if (contextLen != 0) {
    throw StateError('Expected empty certificate_request_context');
  }

  final certLen = (certMsg[8] << 16) | (certMsg[9] << 8) | certMsg[10];

  final certStart = 11;
  final certEnd = certStart + certLen;

  if (certEnd > certMsg.length) {
    throw StateError('Truncated certificate entry');
  }

  return certMsg.sublist(certStart, certEnd);
}

Uint8List _tpBytes(int id, Uint8List value) {
  return Uint8List.fromList([
    ..._encodeVarInt(id),
    ..._encodeVarInt(value.length),
    ...value,
  ]);
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (identical(a, b)) return true;
  if (a.length != b.length) return false;

  // Constant-time compare to avoid timing leaks.
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

// =============================================================
// One‑shot helper used by QuicServerSession
// =============================================================

// =============================================================
// TLS 1.3 CertificateVerify helpers
// Put these in tls_server_handshake.dart
// =============================================================

Uint8List _tls13CertificateVerifyInput({
  required String contextString,
  required Uint8List transcriptHash,
}) {
  // TLS 1.3 CertificateVerify input:
  // 64 bytes of 0x20, then context string, then 0x00, then transcript hash
  final spaces = Uint8List.fromList(List<int>.filled(64, 0x20));
  final context = Uint8List.fromList(utf8.encode(contextString));

  return Uint8List.fromList([...spaces, ...context, 0x00, ...transcriptHash]);
}

Uint8List _encodeAsn1Integer(Uint8List bytes) {
  // Strip leading zeros
  int i = 0;
  while (i < bytes.length - 1 && bytes[i] == 0x00) {
    i++;
  }
  Uint8List v = bytes.sublist(i);

  // If the high bit is set, prefix 0x00 so ASN.1 INTEGER stays positive
  if (v.isNotEmpty && (v[0] & 0x80) != 0) {
    v = Uint8List.fromList([0x00, ...v]);
  }

  return Uint8List.fromList([
    0x02, // INTEGER
    v.length,
    ...v,
  ]);
}

Uint8List _derEncodeEcdsaSignature(Uint8List rawSig) {
  // Expect raw P-256 signature: 32-byte r || 32-byte s
  if (rawSig.length != 64) {
    throw StateError(
      'Expected raw ECDSA signature of 64 bytes (r||s), got ${rawSig.length}',
    );
  }

  final r = rawSig.sublist(0, 32);
  final s = rawSig.sublist(32, 64);

  final rDer = _encodeAsn1Integer(r);
  final sDer = _encodeAsn1Integer(s);

  final seqBody = Uint8List.fromList([...rDer, ...sDer]);

  return Uint8List.fromList([
    0x30, // SEQUENCE
    seqBody.length,
    ...seqBody,
  ]);
}

Uint8List _ensureDerEncodedEcdsaSignature(Uint8List sig) {
  // If already ASN.1 DER SEQUENCE, keep it
  if (sig.isNotEmpty && sig[0] == 0x30) {
    return sig;
  }

  // Otherwise assume raw r||s and convert
  return _derEncodeEcdsaSignature(sig);
}

// =============================================================
// CertificateVerify (PATCHED)
// Put this in tls_server_handshake.dart
// =============================================================

Uint8List buildServerCertificateVerify({
  required EcdsaCert cert,
  required Uint8List transcriptHash,
}) {
  // TLS 1.3 server CertificateVerify context string
  const contextString = 'TLS 1.3, server CertificateVerify';

  final toBeSigned = _tls13CertificateVerifyInput(
    contextString: contextString,
    transcriptHash: transcriptHash,
  );

  // For ecdsa_secp256r1_sha256, sign SHA-256 over the CertificateVerify input
  final hash = crypto.sha256.convert(toBeSigned).bytes;

  Uint8List signature = Uint8List.fromList(ecdsaSign(cert.privateKey, hash));

  // TLS requires ASN.1 DER encoding for ECDSA signatures
  signature = _ensureDerEncodedEcdsaSignature(signature);

  final bodyLen = 2 + 2 + signature.length;

  return Uint8List.fromList([
    0x0f, // HandshakeType.certificate_verify
    (bodyLen >> 16) & 0xff,
    (bodyLen >> 8) & 0xff,
    bodyLen & 0xff,

    // signature_algorithm = ecdsa_secp256r1_sha256
    (ecdsaP256Sha256 >> 8) & 0xff,
    ecdsaP256Sha256 & 0xff,

    // signature vector length
    (signature.length >> 8) & 0xff,
    signature.length & 0xff,

    ...signature,
  ]);
}

// =============================================================
// One-shot server handshake artifact builder (PATCHED)
// Put this in tls_server_handshake.dart
// =============================================================

ServerHandshakeArtifacts buildServerHandshakeArtifacts({
  required Uint8List serverRandom,
  required Uint8List serverPublicKey,
  required EcdsaCert serverCert,

  /// Prefix up to and including ServerHello:
  /// ClientHello || ServerHello
  required Uint8List transcriptPrefixBeforeCertVerify,

  // REQUIRED for correct QUIC server transport parameters
  required Uint8List originalDestinationConnectionId,
  required Uint8List initialSourceConnectionId,

  // For quic-go example client
  String alpnProtocol = alpnQuicEchoExample,
}) {
  final sh = buildServerHello(
    serverRandom: serverRandom,
    publicKey: serverPublicKey,
    sessionId: Uint8List(0),
    cipherSuite: tlsAes128GcmSha256,
    group: x25519Group,
  );

  final ee = buildEncryptedExtensions([
    BuiltExtension(type: 0x0010, data: buildAlpnExt(alpnProtocol)),
    BuiltExtension(
      type: 0x0039,
      data: buildQuicTransportParameters(
        originalDestinationConnectionId: originalDestinationConnectionId,
        initialSourceConnectionId: initialSourceConnectionId,
      ),
    ),
  ]);

  final cert = buildCertificate([CertificateEntry(cert: serverCert.cert)]);

  final extractedCertDer = _extractFirstCertDerFromCertificateHandshake(cert);

  final originalHash = createHash(serverCert.cert);
  final extractedHash = createHash(extractedCertDer);

  print('Original cert hash : ${fingerprint(originalHash)}');
  print('Extracted cert hash: ${fingerprint(extractedHash)}');

  if (!_bytesEqual(originalHash, extractedHash)) {
    throw StateError(
      'Certificate DER changed while building TLS Certificate message',
    );
  }

  // TLS 1.3 CertificateVerify signs over:
  // ClientHello || ServerHello || EncryptedExtensions || Certificate
  final transcriptHashBeforeCertVerify = createHash(
    Uint8List.fromList([...transcriptPrefixBeforeCertVerify, ...ee, ...cert]),
  );

  final cv = buildServerCertificateVerify(
    cert: serverCert,
    transcriptHash: transcriptHashBeforeCertVerify,
  );

  return ServerHandshakeArtifacts(
    serverHello: sh,
    encryptedExtensions: ee,
    certificate: cert,
    certificateVerify: cv,
  );
}

// =============================================================
// _maybeHandleClientHello() (PATCHED)
// Put this in quic_server_session.dart
// =============================================================

// =============================================================
// Demo main (runnable)
// =============================================================

// void main() {
//   final keyPair = KeyPair.generate();
//   final serverCert = generateSelfSignedCertificate();

//   final serverRandom = Uint8List.fromList(
//     List.generate(32, (_) => math.Random.secure().nextInt(256)),
//   );

//   final dummyTranscriptHash = createHash(Uint8List(0));

//   final artifacts = buildServerHandshakeArtifacts(
//     serverRandom: serverRandom,
//     serverPublicKey: keyPair.publicKeyBytes,
//     serverCert: serverCert,
//     transcriptHashBeforeCertVerify: dummyTranscriptHash,
//   );

//   print('ServerHello:        ${HEX.encode(artifacts.serverHello)}');
//   print('EncryptedExtensions:${HEX.encode(artifacts.encryptedExtensions)}');
//   print('Certificate:        ${HEX.encode(artifacts.certificate)}');
//   print('CertificateVerify:  ${HEX.encode(artifacts.certificateVerify)}');
// }
