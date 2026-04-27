// lib/handshake/certificate_verify.dart
import 'dart:typed_data';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic/elliptic.dart';
import 'package:hex/hex.dart';

// certificate_verify.dart
// import 'dart:typed_data';
import '../buffer.dart';
import '../cipher/cert_utils.dart';
import '../cipher/ecdsa.dart';
import '../cipher/hash.dart';
import 'tls_msg.dart';

Uint8List _concat(List<Uint8List> items) {
  final total = items.fold<int>(0, (s, b) => s + b.length);
  final out = Uint8List(total);
  int o = 0;
  for (final x in items) {
    out.setRange(o, o + x.length, x);
    o += x.length;
  }
  return out;
}

Uint8List _u16(int v) => Uint8List.fromList([(v >> 8) & 0xff, v & 0xff]);

/// ✅ Build TLS 1.3 CertificateVerify using deterministic ECDSA (RFC 6979)
Uint8List buildCertificateVerify({
  required Uint8List privateKeyBytes, // server P‑256 private scalar (32 bytes)
  required Uint8List transcriptHash, // SHA256(CH || SH || EE || Cert)
}) {
  // -------------------------------------------------------------
  // ✅ Construct the *exact* TLS 1.3 "to-be-signed" structure
  // -------------------------------------------------------------
  //
  //  struct {
  //      opaque content[64] = 0x20...;
  //      opaque context_string = "TLS 1.3, server CertificateVerify";
  //      opaque zero_byte = 0x00;
  //      opaque transcript_hash[Hash.length];
  //  } CertificateVerifyInput;
  //
  final prefix = Uint8List.fromList(List.filled(64, 0x20));
  final context = Uint8List.fromList(
    utf8.encode("TLS 1.3, server CertificateVerify"),
  );
  final zero = Uint8List.fromList([0x00]);

  final toBeSigned = _concat([prefix, context, zero, transcriptHash]);

  // -------------------------------------------------------------
  // ✅ Deterministic ECDSA (RFC6979) using package:ecdsa
  // -------------------------------------------------------------
  final priv = PrivateKey.fromBytes(getP256(), privateKeyBytes.toList());

  // The ecdsa package signs arbitrary bytes, so we pass toBeSigned directly
  final sig = signature(priv, toBeSigned);

  // DER encode (TLS 1.3 requires DER ECDSA signatures)
  final der = sig.toASN1();

  // -------------------------------------------------------------
  // ✅ Build CertificateVerify handshake message
  // -------------------------------------------------------------
  //
  //  struct {
  //     SignatureScheme algorithm = 0x0403;
  //     opaque signature<0..2^16-1>;
  //  }
  //
  const int algorithm = 0x0403; // ecdsa_secp256r1_sha256

  final body = _concat([
    _u16(algorithm),
    _u16(der.length),
    Uint8List.fromList(der),
  ]);

  final hdr = Uint8List.fromList([
    0x0F, // HandshakeType::certificate_verify
    (body.length >> 16) & 0xff,
    (body.length >> 8) & 0xff,
    body.length & 0xff,
  ]);

  return _concat([hdr, body]);
}

/// ✅ Optional helper to verify CertificateVerify signatures
bool verifyCertificateVerify({
  required Uint8List publicKeyBytes,
  required Uint8List transcriptHash,
  required Uint8List signatureBytes,
}) {
  final pub = PublicKey.fromHex(getP256(), HEX.encode(publicKeyBytes));
  final sig = Signature.fromASN1(signatureBytes);
  return verify(pub, transcriptHash.toList(), sig);
}

class CertificateVerify extends TlsHandshakeMessage {
  final int algorithm;
  final Uint8List signature;

  CertificateVerify({required this.algorithm, required this.signature})
    : super(0x0F);

  // ---------------------------------------------------------
  // ✅ PARSER
  // ---------------------------------------------------------
  static CertificateVerify parse(QuicBuffer buf) {
    final alg = buf.pullUint16();
    final sigLen = buf.pullUint16();
    final sig = buf.pullBytes(sigLen);

    return CertificateVerify(algorithm: alg, signature: sig);
  }

  // ---------------------------------------------------------
  // ✅ BUILDER  (matches JS build_certificate_verify)
  // ---------------------------------------------------------
  Uint8List build() {
    final body = BytesBuilder()
      ..add([(algorithm >> 8) & 0xFF, algorithm & 0xFF])
      ..add([(signature.length >> 8) & 0xFF, signature.length & 0xFF])
      ..add(signature);

    final bodyBytes = body.toBytes();

    final header = [
      msgType,
      (bodyBytes.length >> 16) & 0xFF,
      (bodyBytes.length >> 8) & 0xFF,
      bodyBytes.length & 0xFF,
    ];

    return Uint8List.fromList([...header, ...bodyBytes]);
  }

  @override
  String toString() =>
      "✅ CertificateVerify(alg=0x${algorithm.toRadixString(16)})";
}

void verifyServerCertificateAndSignature({
  required Uint8List clientHello,
  required Uint8List serverHello,
  required Uint8List encryptedExtensions,
  required Uint8List certificateHandshake,
  required Uint8List certificateVerifyHandshake,
  required Uint8List pinnedCertSha256,
}) {
  // ------------------------------
  // Extract certificate DER
  // ------------------------------
  final certDer = extractFirstCertDerFromCertificateHandshake(
    certificateHandshake,
  );

  // ------------------------------
  // Hash certificate DER
  // ------------------------------
  final certHash = createHash(certDer);

  print('🔐 [CERT] Extracted DER SHA256 = ${HEX.encode(certHash)}');
  print('📌 [PIN ] Pinned cert SHA256  = ${HEX.encode(pinnedCertSha256)}');

  // ------------------------------
  // Pin comparison
  // ------------------------------
  if (!constantTimeEquals(certHash, pinnedCertSha256)) {
    print('❌ [PIN ] MISMATCH');
    throw StateError('❌ Certificate pinning failed');
  } else {
    print('✅ [PIN ] Match');
  }

  // ------------------------------
  // Parse CertificateVerify
  // ------------------------------
  final sigAlg =
      (certificateVerifyHandshake[4] << 8) | certificateVerifyHandshake[5];

  if (sigAlg != 0x0403) {
    throw StateError(
      'Unsupported signature algorithm 0x${sigAlg.toRadixString(16)}',
    );
  }

  final sigLen =
      (certificateVerifyHandshake[6] << 8) | certificateVerifyHandshake[7];

  final signature = certificateVerifyHandshake.sublist(8, 8 + sigLen);

  print('✍️  [CV ] Signature len = $sigLen');
  print('✍️  [CV ] Signature DER = ${HEX.encode(signature)}');

  // ------------------------------
  // Transcript hash
  // ------------------------------
  final transcriptHash = createHash(
    Uint8List.fromList([
      ...clientHello,
      ...serverHello,
      ...encryptedExtensions,
      ...certificateHandshake,
    ]),
  );

  print('📜 [CV ] Transcript hash = ${HEX.encode(transcriptHash)}');

  // ------------------------------
  // TLS 1.3 signing input
  // ------------------------------
  final input = tls13CertificateVerifyInput(
    contextString: 'TLS 1.3, server CertificateVerify',
    transcriptHash: transcriptHash,
  );

  final inputHash = sha256.convert(input).bytes;
  print('📜 [CV ] Signing input SHA256 = ${HEX.encode(inputHash)}');

  // ------------------------------
  // Extract public key
  // ------------------------------
  final publicKey = extractEcdsaPublicKeyFromCertificateDer(certDer);
  print('🔑 [CERT] Server public key = ${HEX.encode(publicKey)}');
  print('🔑 [CERT] Public key hash   = ${HEX.encode(createHash(publicKey))}');

  // ------------------------------
  // Verify ECDSA signature
  // ------------------------------
  final ok = ecdsaVerify(publicKey, inputHash, signature);

  if (!ok) {
    print('❌ [CV ] Signature verification FAILED');
    throw StateError('❌ CertificateVerify signature invalid');
  }

  print('✅ Server certificate verified');
}

bool constantTimeEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  int diff = 0;
  for (int i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

Uint8List tls13CertificateVerifyInput({
  required String contextString,
  required Uint8List transcriptHash,
}) {
  final prefix = Uint8List.fromList(List.filled(64, 0x20));
  final context = Uint8List.fromList(utf8.encode(contextString));

  return Uint8List.fromList([...prefix, ...context, 0x00, ...transcriptHash]);
}

Uint8List extractFirstCertDerFromCertificateHandshake(Uint8List certHandshake) {
  // TLS Handshake header:
  //   byte 0  : msg_type (0x0b)
  //   byte 1-3: length
  if (certHandshake.length < 11 || certHandshake[0] != 0x0b) {
    throw StateError('Not a TLS Certificate handshake message');
  }

  // byte 4: certificate_request_context length (must be 0 for server)
  final contextLen = certHandshake[4];
  if (contextLen != 0) {
    throw StateError('Non-empty certificate_request_context not supported');
  }

  // byte 5-7: certificate_list length (ignored here)
  // byte 8-10: first certificate length
  final certLen =
      (certHandshake[8] << 16) | (certHandshake[9] << 8) | certHandshake[10];

  final start = 11;
  final end = start + certLen;

  if (end > certHandshake.length) {
    throw StateError('Truncated certificate DER');
  }

  return certHandshake.sublist(start, end);
}
