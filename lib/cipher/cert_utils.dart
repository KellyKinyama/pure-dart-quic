// import 'dart:convert';
// import 'dart:typed_data';

// // import 'package:crypto/crypto.dart' as crypto;
// import 'package:basic_utils/basic_utils.dart';
// import 'package:pure_dart_quic/cipher/hash.dart';

// import 'fingerprint.dart';

// // Helper to decode PEM to DER (your existing function)
// Uint8List decodePemToDer(String pem) {
//   var startsWith = [
//     '-----BEGIN PUBLIC KEY-----',
//     '-----BEGIN PRIVATE KEY-----',
//     '-----BEGIN CERTIFICATE-----',
//     '-----BEGIN EC PRIVATE KEY-----',
//   ];
//   var endsWith = [
//     '-----END PUBLIC KEY-----',
//     '-----END PRIVATE KEY-----',
//     '-----END CERTIFICATE-----',
//     '-----END EC PRIVATE KEY-----',
//   ];

//   for (var s in startsWith) {
//     if (pem.startsWith(s)) pem = pem.substring(s.length);
//   }

//   for (var s in endsWith) {
//     if (pem.endsWith(s)) pem = pem.substring(0, pem.length - s.length);
//   }

//   pem = pem.replaceAll('\n', '');
//   pem = pem.replaceAll('\r', '');
//   return Uint8List.fromList(base64.decode(pem));
// }

// class EcdsaCert {
//   Uint8List cert;
//   Uint8List privateKey; // Raw private key (scalar)
//   Uint8List publickKey; // Raw public key (uncompressed point)
//   Uint8List fingerPrint;
//   EcdsaCert({
//     required this.privateKey,
//     required this.publickKey,
//     required this.cert,
//     required this.fingerPrint,
//   });

//   // factory EcdsaCert.fromPem({required String certPem, required String publickKeyPem, required String privateKeyPem}){

//   // }

//   // factory EcdsaCert.fromConstPem(){
//   //   X509Utils.

//   // }
// }

// EcdsaCert generateSelfSignedCertificate() {
//   var pair = CryptoUtils.generateEcKeyPair();
//   var privKey = pair.privateKey as ECPrivateKey;
//   var pubKey = pair.publicKey as ECPublicKey;
//   var dn = {'CN': '127.0.0.1'};
//   final san = ["127.0.0.1", "localhost"];
//   var csr = X509Utils.generateEccCsrPem(
//     dn,
//     privKey,
//     pubKey,
//     san: ["127.0.0.1", "localhost"],
//   );

//   // Encode private key to PEM
//   String privateKeyPem = CryptoUtils.encodeEcPrivateKeyToPem(privKey);
//   print("Private Key PEM:\n$privateKeyPem\n");

//   // Encode public key to PEM
//   String publicKeyPem = CryptoUtils.encodeEcPublicKeyToPem(pubKey);
//   print("Public Key PEM:\n$publicKeyPem\n");

//   // var x509PEM = X509Utils.generateSelfSignedCertificate(privKey, csr, 13);

//   var x509PEM = X509Utils.generateSelfSignedCertificate(
//     privKey,
//     csr,
//     13,
//     sans: san,
//   );

//   // Extract raw public key and private key from the Pointy Castle objects
//   Uint8List rawPublicKey = _encodeECPublicKeyToRaw(pubKey);
//   Uint8List rawPrivateKey = encodeECPrivateKeyToRaw(privKey);

//   // print("Raw Public Key length: ${rawPublicKey.length}");
//   final certDer = decodePemToDer(x509PEM);
//   print("Certificate PEM: $x509PEM");
//   // final fingerPrint = base64.decode(fingerprint(certDer).replaceAll(":", ""));
//   final fingerPrint = createHash(certDer);
//   print("Certificate finger print: ${fingerprint(fingerPrint)}");

//   // print("Certificate PEM:\n$x509PEM\n");
//   return EcdsaCert(
//     privateKey: rawPrivateKey,
//     publickKey: rawPublicKey,
//     cert: certDer,
//     fingerPrint: fingerPrint,
//   );
// }

// // New helper to extract raw public key bytes (uncompressed)
// Uint8List _encodeECPublicKeyToRaw(ECPublicKey publicKey) {
//   // Pointy Castle's ECPublicKey stores the Q (point)
//   // For prime256v1, coordinates are 32 bytes.
//   // final expectedByteLength = (publicKey.parameters!.curve.fieldSize + 7) ~/ 8;

//   // Use toBytesPadded directly on the BigInt from the ECPoint
//   final paddedX = bigIntToUint8List(
//     publicKey.Q!.x!.toBigInteger()!,
//   ); //.toBytesPadded(expectedByteLength);
//   final paddedY = bigIntToUint8List(
//     publicKey.Q!.y!.toBigInteger()!,
//   ); //.toBytesPadded(expectedByteLength);
//   print("Padded X length: ${paddedX.length}");
//   print("Padded Y length: ${paddedY.length}");
//   // Ensure x and y are 32 bytes long, padded with leading zeros if necessary

//   return Uint8List.fromList([0x04, ...paddedX, ...paddedY]);
// }

// // New helper to extract raw private key bytes (scalar)
// Uint8List encodeECPrivateKeyToRaw(ECPrivateKey privateKey) {
//   // Pointy Castle's ECPrivateKey stores the d (scalar)
//   final dBytes = bigIntToUint8List(privateKey.d!);

//   // Ensure the private key is 32 bytes long for prime256v1
//   final paddedD = Uint8List(32);
//   paddedD.setRange(32 - dBytes.length, 32, dBytes);
//   return paddedD;
// }

// Uint8List bigIntToUint8List(BigInt bigInt) =>
//     bigIntToByteData(bigInt).buffer.asUint8List();

// ByteData bigIntToByteData(BigInt bigInt) {
//   final data = ByteData((bigInt.bitLength / 8).ceil());
//   var _bigInt = bigInt;

//   for (var i = 1; i <= data.lengthInBytes; i++) {
//     data.setUint8(data.lengthInBytes - i, _bigInt.toUnsigned(8).toInt());
//     _bigInt = _bigInt >> 8;
//   }

//   return data;
// }

import 'dart:convert';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:hex/hex.dart';
import 'package:pointycastle/asn1.dart';

import 'ecdsa.dart';
import 'fingerprint.dart';
import 'hash.dart';

/// ------------------------------------------------------------
/// Decode PEM -> DER
/// ------------------------------------------------------------
Uint8List decodePemToDer(String pem) {
  const startsWith = [
    '-----BEGIN PUBLIC KEY-----',
    '-----BEGIN PRIVATE KEY-----',
    '-----BEGIN CERTIFICATE-----',
    '-----BEGIN EC PRIVATE KEY-----',
  ];

  const endsWith = [
    '-----END PUBLIC KEY-----',
    '-----END PRIVATE KEY-----',
    '-----END CERTIFICATE-----',
    '-----END EC PRIVATE KEY-----',
  ];

  for (final s in startsWith) {
    if (pem.startsWith(s)) {
      pem = pem.substring(s.length);
    }
  }

  for (final s in endsWith) {
    if (pem.endsWith(s)) {
      pem = pem.substring(0, pem.length - s.length);
    }
  }

  pem = pem.replaceAll('\n', '');
  pem = pem.replaceAll('\r', '');

  return Uint8List.fromList(base64.decode(pem));
}

/// ------------------------------------------------------------
/// Local certificate model used by the QUIC server
/// ------------------------------------------------------------
class EcdsaCert {
  Uint8List cert; // DER certificate
  Uint8List privateKey; // Raw private key scalar (32 bytes)
  Uint8List publickKey; // Raw public key (0x04 || X || Y)
  Uint8List fingerPrint; // SHA-256(cert DER)

  EcdsaCert({
    required this.privateKey,
    required this.publickKey,
    required this.cert,
    required this.fingerPrint,
  });
}

/// ------------------------------------------------------------
/// Browser-compatible self-signed certificate generator
///
/// Produces:
/// - ECDSA P-256 certificate
/// - validity = 13 days
/// - subject CN = 127.0.0.1
/// - SAN:
///     * IP:127.0.0.1
///     * DNS:localhost
/// ------------------------------------------------------------
EcdsaCert generateSelfSignedCertificate() {
  final pair = CryptoUtils.generateEcKeyPair();
  final privKey = pair.privateKey as ECPrivateKey;
  final pubKey = pair.publicKey as ECPublicKey;

  final privateKeyPem = CryptoUtils.encodeEcPrivateKeyToPem(privKey);
  print("Private Key PEM:\n$privateKeyPem\n");

  final publicKeyPem = CryptoUtils.encodeEcPublicKeyToPem(pubKey);
  print("Public Key PEM:\n$publicKeyPem\n");

  final certPem = _generateSelfSignedCertificatePemEcdsa(
    privateKey: privKey,
    publicKey: pubKey,
    subjectDn: const {'CN': '127.0.0.1'},
    days: 13,
    sans: const ['127.0.0.1', 'localhost'],
  );

  final certDer = decodePemToDer(certPem);
  print("Certificate PEM: $certPem");

  final rawPublicKey = _encodeECPublicKeyToRaw(pubKey);
  final rawPrivateKey = encodeECPrivateKeyToRaw(privKey);

  final fingerPrint = createHash(certDer);
  print("Certificate finger print: ${fingerprint(fingerPrint)}");

  return EcdsaCert(
    privateKey: rawPrivateKey,
    publickKey: rawPublicKey,
    cert: certDer,
    fingerPrint: fingerPrint,
  );
}

/// ------------------------------------------------------------
/// Build a self-signed X.509 certificate (ECDSA / P-256)
/// ------------------------------------------------------------
String _generateSelfSignedCertificatePemEcdsa({
  required ECPrivateKey privateKey,
  required ECPublicKey publicKey,
  required Map<String, String> subjectDn,
  required int days,
  required List<String> sans,
}) {
  // TBSCertificate
  final tbs = ASN1Sequence();

  // version = v3
  final version = ASN1Object(tag: 0xA0);
  version.valueBytes = ASN1Integer.fromtInt(2).encode();
  tbs.add(version);

  // serialNumber = 1
  tbs.add(ASN1Integer.fromtInt(1));

  // signature algorithm = ecdsa-with-SHA256
  final sigAlg = _algorithmIdentifierEcdsaSha256();
  tbs.add(sigAlg);

  // issuer = subject (self-signed)
  final issuer = _buildName(subjectDn);
  tbs.add(issuer);

  // validity
  final now = DateTime.now().toUtc();
  final validity = ASN1Sequence()
    ..add(ASN1UtcTime(now))
    ..add(ASN1UtcTime(now.add(Duration(days: days))));
  tbs.add(validity);

  // subject
  final subject = _buildName(subjectDn);
  tbs.add(subject);

  // SubjectPublicKeyInfo
  final spkiDer = decodePemToDer(CryptoUtils.encodeEcPublicKeyToPem(publicKey));
  final spkiAsn1 = ASN1Parser(spkiDer).nextObject()!;
  tbs.add(spkiAsn1);

  // Extensions [3] EXPLICIT
  final extensions = ASN1Sequence();

  // SAN
  extensions.add(_buildSubjectAltNameExtension(sans));

  // BasicConstraints: CA=false
  extensions.add(_buildBasicConstraintsExtension(cA: false));

  // KeyUsage: digitalSignature
  extensions.add(_buildKeyUsageDigitalSignatureExtension());

  // ExtendedKeyUsage: serverAuth
  extensions.add(_buildExtendedKeyUsageServerAuthExtension());

  final extObj = ASN1Object(tag: 0xA3);
  extObj.valueBytes = extensions.encode();
  tbs.add(extObj);

  // Sign TBSCertificate using ECDSA over SHA-256(tbsDer)
  final tbsDer = tbs.encode();
  final digest = Uint8List.fromList(crypto.sha256.convert(tbsDer).bytes);
  final rawPriv = encodeECPrivateKeyToRaw(privateKey);

  final sig = Uint8List.fromList(ecdsaSign(rawPriv, digest));
  final derSig = _ensureDerEncodedEcdsaSignature(sig);

  // Final certificate = SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  final cert = ASN1Sequence()
    ..add(tbs)
    ..add(sigAlg)
    ..add(ASN1BitString(stringValues: derSig));

  final pemBody = base64.encode(cert.encode());
  final chunks = StringUtils.chunk(pemBody, 64);

  return '-----BEGIN CERTIFICATE-----\n'
      '${chunks.join('\n')}\n'
      '-----END CERTIFICATE-----';
}

/// ------------------------------------------------------------
/// ASN.1 / X.509 helpers
/// ------------------------------------------------------------

ASN1Sequence _algorithmIdentifierEcdsaSha256() {
  // ecdsa-with-SHA256 = 1.2.840.10045.4.3.2
  return ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromIdentifierString('1.2.840.10045.4.3.2'));
}

ASN1Sequence _buildName(Map<String, String> dn) {
  final seq = ASN1Sequence();

  dn.forEach((k, value) {
    final oid = _dnOid(k);

    ASN1Object valueObj;
    if (StringUtils.isAscii(value)) {
      valueObj = ASN1PrintableString(stringValue: value);
    } else {
      valueObj = ASN1UTF8String(utf8StringValue: value);
    }

    final inner = ASN1Sequence()
      ..add(oid)
      ..add(valueObj);

    final set = ASN1Set()..add(inner);
    seq.add(set);
  });

  return seq;
}

ASN1ObjectIdentifier _dnOid(String shortName) {
  switch (shortName) {
    case 'CN':
      return ASN1ObjectIdentifier.fromIdentifierString('2.5.4.3');
    case 'C':
      return ASN1ObjectIdentifier.fromIdentifierString('2.5.4.6');
    case 'ST':
      return ASN1ObjectIdentifier.fromIdentifierString('2.5.4.8');
    case 'L':
      return ASN1ObjectIdentifier.fromIdentifierString('2.5.4.7');
    case 'O':
      return ASN1ObjectIdentifier.fromIdentifierString('2.5.4.10');
    case 'OU':
      return ASN1ObjectIdentifier.fromIdentifierString('2.5.4.11');
    default:
      throw ArgumentError('Unsupported DN attribute: $shortName');
  }
}

ASN1Sequence _buildSubjectAltNameExtension(List<String> sans) {
  final sanList = ASN1Sequence();

  for (final s in sans) {
    if (_isIpv4Literal(s)) {
      // iPAddress SAN = GeneralName [7] => tag 0x87
      // Value must be raw IP bytes
      final ipObj = ASN1Object(tag: 0x87);
      ipObj.valueBytes = _ipv4LiteralToBytes(s);
      sanList.add(ipObj);
    } else {
      // dNSName SAN = GeneralName [2] => tag 0x82
      // Value is the raw ASCII hostname bytes
      final dnsObj = ASN1Object(tag: 0x82);
      dnsObj.valueBytes = Uint8List.fromList(ascii.encode(s));
      sanList.add(dnsObj);
    }
  }

  return ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromIdentifierString('2.5.29.17'))
    ..add(ASN1OctetString(octets: sanList.encode()));
}

ASN1Sequence _buildBasicConstraintsExtension({required bool cA}) {
  final basicConstraintsValue = ASN1Sequence();

  if (cA) {
    basicConstraintsValue.add(ASN1Boolean(cA));
  }

  return ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromIdentifierString('2.5.29.19'))
    ..add(ASN1Boolean(true)) // critical
    ..add(ASN1OctetString(octets: basicConstraintsValue.encode()));
}

ASN1Sequence _buildKeyUsageDigitalSignatureExtension() {
  // digitalSignature bit set
  // KeyUsage is BIT STRING wrapped inside OCTET STRING
  final keyUsageBytes = Uint8List.fromList(<int>[
    0x03, // BIT STRING
    0x02, // length
    0x07, // 7 unused bits
    0x80, // digitalSignature
  ]);

  return ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromIdentifierString('2.5.29.15'))
    ..add(ASN1Boolean(true)) // critical
    ..add(ASN1OctetString(octets: keyUsageBytes));
}

ASN1Sequence _buildExtendedKeyUsageServerAuthExtension() {
  // serverAuth = 1.3.6.1.5.5.7.3.1
  final ekuList = ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromIdentifierString('1.3.6.1.5.5.7.3.1'));

  return ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromIdentifierString('2.5.29.37'))
    ..add(ASN1OctetString(octets: ekuList.encode()));
}

/// ------------------------------------------------------------
/// IP helpers
/// ------------------------------------------------------------
bool _isIpv4Literal(String s) {
  final parts = s.split('.');
  if (parts.length != 4) return false;

  for (final p in parts) {
    if (p.isEmpty) return false;
    final v = int.tryParse(p);
    if (v == null || v < 0 || v > 255) return false;
  }

  return true;
}

Uint8List _ipv4LiteralToBytes(String s) {
  final parts = s.split('.').map(int.parse).toList();
  return Uint8List.fromList(parts);
}

/// ------------------------------------------------------------
/// ECDSA signature DER helpers
/// ------------------------------------------------------------
Uint8List _encodeAsn1Integer(Uint8List bytes) {
  int i = 0;
  while (i < bytes.length - 1 && bytes[i] == 0x00) {
    i++;
  }

  Uint8List v = bytes.sublist(i);

  // Prefix 0x00 if high bit is set so ASN.1 INTEGER stays positive
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
  // Raw P-256 signature must be 32-byte r || 32-byte s
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
  // If already DER (SEQUENCE), keep it as-is
  if (sig.isNotEmpty && sig[0] == 0x30) {
    return sig;
  }

  // Otherwise assume raw r||s
  return _derEncodeEcdsaSignature(sig);
}

/// ------------------------------------------------------------
/// Existing helpers you already had
/// ------------------------------------------------------------
Uint8List _encodeECPublicKeyToRaw(ECPublicKey publicKey) {
  final paddedX = bigIntToUint8List(publicKey.Q!.x!.toBigInteger()!);
  final paddedY = bigIntToUint8List(publicKey.Q!.y!.toBigInteger()!);

  print("Padded X length: ${paddedX.length}");
  print("Padded Y length: ${paddedY.length}");

  return Uint8List.fromList([0x04, ...paddedX, ...paddedY]);
}

Uint8List encodeECPrivateKeyToRaw(ECPrivateKey privateKey) {
  final dBytes = bigIntToUint8List(privateKey.d!);

  final paddedD = Uint8List(32);
  paddedD.setRange(32 - dBytes.length, 32, dBytes);
  return paddedD;
}

Uint8List bigIntToUint8List(BigInt bigInt) =>
    bigIntToByteData(bigInt).buffer.asUint8List();

ByteData bigIntToByteData(BigInt bigInt) {
  final data = ByteData((bigInt.bitLength / 8).ceil());
  var _bigInt = bigInt;

  for (var i = 1; i <= data.lengthInBytes; i++) {
    data.setUint8(data.lengthInBytes - i, _bigInt.toUnsigned(8).toInt());
    _bigInt = _bigInt >> 8;
  }

  return data;
}

/// ------------------------------------------------------------
/// Load an EC certificate + EC private key from PEM strings
/// and convert them into your existing EcdsaCert model.
/// ------------------------------------------------./// ------------------------------------------------------------
/// Supports both:
///   - -----BEGIN EC PRIVATE KEY-----
///   - -----BEGIN PRIVATE KEY-----
/// depending on what basic_utils can parse directly.
/// ------------------------------------------------------------
ECPrivateKey _parseEcPrivateKeyPem(String pem) {
  try {
    return CryptoUtils.ecPrivateKeyFromPem(pem);
  } catch (_) {
    final der = decodePemToDer(pem);
    return CryptoUtils.ecPrivateKeyFromDerBytes(der);
  }
}

/// ------------------------------------------------------------
/// Derive raw uncompressed public key bytes from raw private key
/// using elliptic package:
///   0x04 || X || Y
/// ------------------------------------------------------------
Uint8List _deriveRawPublicKeyFromRawPrivate(Uint8List rawPrivateKey) {
  final curve = elliptic.getP256();
  final priv = elliptic.PrivateKey.fromBytes(curve, rawPrivateKey);
  final pubHex = priv.publicKey.toHex(); // usually uncompressed 04 + X + Y
  return Uint8List.fromList(HEX.decode(pubHex));
}

EcdsaCert loadEcdsaCertFromPemStrings({
  required String certPem,
  required String privateKeyPem,
}) {
  final certDer = decodePemToDer(certPem);

  final ecPrivateKey = _parseEcPrivateKeyPem(privateKeyPem);
  final rawPrivateKey = encodeECPrivateKeyToRaw(ecPrivateKey);

  // Derive uncompressed public key (0x04 || X || Y) from the private key.
  final rawPublicKey = _deriveRawPublicKeyFromRawPrivate(rawPrivateKey);

  final fingerPrint = createHash(certDer);

  print("Loaded certificate fingerprint: ${fingerprint(fingerPrint)}");

  return EcdsaCert(
    privateKey: rawPrivateKey,
    publickKey: rawPublicKey,
    cert: certDer,
    fingerPrint: fingerPrint,
  );
}

const String kPinnedServerCertPem = r'''-----BEGIN CERTIFICATE-----
MIIBjzCCATSgAwIBAgIUHMcuHcCC9tw+Bxdnijyf2gU3yGswCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MDQyNDA4NDA0M1oXDTI2MDUwNzA4
NDA0M1owFDESMBAGA1UEAwwJMTI3LjAuMC4xMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAERwBy9hNXQFKIG3qREHZD1+TLNupLw6rZqU9WpUKQYkQevC6L943NOh3b
DXZTI6hF4Td/Nc5Navdz9ynctkw96qNkMGIwHQYDVR0OBBYEFLQrArLNuhQtXPzK
zoGg/Bs1C5AfMB8GA1UdIwQYMBaAFLQrArLNuhQtXPzKzoGg/Bs1C5AfMA8GA1Ud
EwEB/wQFMAMBAf8wDwYDVR0RBAgwBocEfwAAATAKBggqhkjOPQQDAgNJADBGAiEA
peSP15oGx1LGVkYgndPFV3S8DEx8ksCrxKNYGAX/P5oCIQDeqBj0eBMNI2op26/U
YwZB7In2blDMUAIJBu4tTaOYBg==
-----END CERTIFICATE-----''';

const String kPinnedServerKeyPem = r'''-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNMkNycItVhMLD4jb
E39R8LG2EnkM8PjL461Gdcj0BT+hRANCAARHAHL2E1dAUogbepEQdkPX5Ms26kvD
qtmpT1alQpBiRB68Lov3jc06HdsNdlMjqEXhN381zk1q93P3Kdy2TD3q
-----END PRIVATE KEY-----''';

/// ------------------------------------------------------------
EcdsaCert loadPinnedServerCertificate() {
  return loadEcdsaCertFromPemStrings(
    certPem: kPinnedServerCertPem,
    privateKeyPem: kPinnedServerKeyPem,
  );
}

/// ===========================================================
/// Certificate public-key extraction
/// ===========================================================

Uint8List extractEcdsaPublicKeyFromCertificateDer(Uint8List certDer) {
  final parser = ASN1Parser(certDer);
  final certSeq = parser.nextObject() as ASN1Sequence;

  final tbs = certSeq.elements![0] as ASN1Sequence;

  // SubjectPublicKeyInfo
  final spki =
      tbs.elements!.firstWhere(
            (e) =>
                e is ASN1Sequence &&
                e.elements?.length == 2 &&
                e.elements![1] is ASN1BitString,
          )
          as ASN1Sequence;

  final bitString = spki.elements![1] as ASN1BitString;
  final pubKey = Uint8List.fromList(bitString.stringValues!);

  if (pubKey.length != 65 || pubKey[0] != 0x04) {
    throw StateError('Expected uncompressed ECDSA P-256 public key');
  }

  return pubKey;
}
