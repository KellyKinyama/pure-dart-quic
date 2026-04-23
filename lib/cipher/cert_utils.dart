import 'dart:convert';
import 'dart:typed_data';

// import 'package:crypto/crypto.dart' as crypto;
import 'package:basic_utils/basic_utils.dart';

import 'fingerprint.dart';

// Helper to decode PEM to DER (your existing function)
Uint8List decodePemToDer(String pem) {
  var startsWith = [
    '-----BEGIN PUBLIC KEY-----',
    '-----BEGIN PRIVATE KEY-----',
    '-----BEGIN CERTIFICATE-----',
    '-----BEGIN EC PRIVATE KEY-----',
  ];
  var endsWith = [
    '-----END PUBLIC KEY-----',
    '-----END PRIVATE KEY-----',
    '-----END CERTIFICATE-----',
    '-----END EC PRIVATE KEY-----',
  ];

  for (var s in startsWith) {
    if (pem.startsWith(s)) pem = pem.substring(s.length);
  }

  for (var s in endsWith) {
    if (pem.endsWith(s)) pem = pem.substring(0, pem.length - s.length);
  }

  pem = pem.replaceAll('\n', '');
  pem = pem.replaceAll('\r', '');
  return Uint8List.fromList(base64.decode(pem));
}

class EcdsaCert {
  Uint8List cert;
  Uint8List privateKey; // Raw private key (scalar)
  Uint8List publickKey; // Raw public key (uncompressed point)
  Uint8List fingerPrint;
  EcdsaCert({
    required this.privateKey,
    required this.publickKey,
    required this.cert,
    required this.fingerPrint,
  });

  // factory EcdsaCert.fromPem({required String certPem, required String publickKeyPem, required String privateKeyPem}){

  // }

  // factory EcdsaCert.fromConstPem(){
  //   X509Utils.

  // }
}

EcdsaCert generateSelfSignedCertificate() {
  var pair = CryptoUtils.generateEcKeyPair();
  var privKey = pair.privateKey as ECPrivateKey;
  var pubKey = pair.publicKey as ECPublicKey;
  var dn = {'CN': 'localhost'};
  var csr = X509Utils.generateEccCsrPem(dn, privKey, pubKey);

  // Encode private key to PEM
  String privateKeyPem = CryptoUtils.encodeEcPrivateKeyToPem(privKey);
  print("Private Key PEM:\n$privateKeyPem\n");

  // Encode public key to PEM
  String publicKeyPem = CryptoUtils.encodeEcPublicKeyToPem(pubKey);
  print("Public Key PEM:\n$publicKeyPem\n");

  var x509PEM = X509Utils.generateSelfSignedCertificate(privKey, csr, 13);

  // Extract raw public key and private key from the Pointy Castle objects
  Uint8List rawPublicKey = _encodeECPublicKeyToRaw(pubKey);
  Uint8List rawPrivateKey = encodeECPrivateKeyToRaw(privKey);

  // print("Raw Public Key length: ${rawPublicKey.length}");
  final certDer = decodePemToDer(x509PEM);
  print("Certificate PEM: $x509PEM");
  final fingerPrint = base64.decode(fingerprint(certDer).replaceAll(":", ""));

  print("Certificate finger print: ${fingerprint(certDer)}");

  // print("Certificate PEM:\n$x509PEM\n");
  return EcdsaCert(
    privateKey: rawPrivateKey,
    publickKey: rawPublicKey,
    cert: certDer,
    fingerPrint: fingerPrint,
  );
}

// New helper to extract raw public key bytes (uncompressed)
Uint8List _encodeECPublicKeyToRaw(ECPublicKey publicKey) {
  // Pointy Castle's ECPublicKey stores the Q (point)
  // For prime256v1, coordinates are 32 bytes.
  // final expectedByteLength = (publicKey.parameters!.curve.fieldSize + 7) ~/ 8;

  // Use toBytesPadded directly on the BigInt from the ECPoint
  final paddedX = bigIntToUint8List(
    publicKey.Q!.x!.toBigInteger()!,
  ); //.toBytesPadded(expectedByteLength);
  final paddedY = bigIntToUint8List(
    publicKey.Q!.y!.toBigInteger()!,
  ); //.toBytesPadded(expectedByteLength);
  print("Padded X length: ${paddedX.length}");
  print("Padded Y length: ${paddedY.length}");
  // Ensure x and y are 32 bytes long, padded with leading zeros if necessary

  return Uint8List.fromList([0x04, ...paddedX, ...paddedY]);
}

// New helper to extract raw private key bytes (scalar)
Uint8List encodeECPrivateKeyToRaw(ECPrivateKey privateKey) {
  // Pointy Castle's ECPrivateKey stores the d (scalar)
  final dBytes = bigIntToUint8List(privateKey.d!);

  // Ensure the private key is 32 bytes long for prime256v1
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
