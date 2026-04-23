import 'dart:typed_data';
// import 'package:hex/hex.dart';
// import 'package:lemon_tls/quic/quic_learn/client/quic_session.dart';

// import '../buffer.dart';
// import '../quic_learn/client/quic_session2.dart';
// import '../quic_learn/constants.dart';
// import '../quic_learn/server/constants.dart';
// import 'client_hello.dart';
// import 'server_hello.dart';
// import 'encrypted_extensions.dart';
// import 'certificate.dart';
// import 'certificate_verify.dart';
// import 'finished.dart';

abstract class TlsHandshakeMessage {
  final int msgType;
  String get typeName => handshakeTypeMap[msgType] ?? 'Unknown';
  TlsHandshakeMessage(this.msgType);
}

class UnknownHandshakeMessage extends TlsHandshakeMessage {
  final Uint8List body;
  UnknownHandshakeMessage(int msgType, this.body) : super(msgType);

  @override
  String toString() =>
      'ℹ️ Parsed UnknownHandshake(type: $msgType, len: ${body.length})';
}

class TlsExtension {
  final int type;
  final Uint8List data;
  int length;

  TlsExtension({required this.type, required this.length, required this.data});

  String get typeName =>
      extensionTypesMap[type] ?? 'Unknown (0x${type.toRadixString(16)})';

  @override
  String toString() => '  - Ext: $typeName, Length: ${data.length}';
}

// --- Helper Maps ---
const Map<int, String> handshakeTypeMap = {
  1: 'ClientHello',
  2: 'ServerHello',
  8: 'EncryptedExtensions',
  11: 'Certificate',
  15: 'CertificateVerify',
  20: 'Finished',
};

const Map<int, String> cipherSuitesMap = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
};

const Map<int, String> extensionTypesMap = {
  0: 'server_name',
  5: 'status_request',
  10: 'supported_groups',
  16: 'application_layer_protocol_negotiation',
  35: 'pre_shared_key',
  43: 'supported_versions',
  44: 'cookie',
  45: 'psk_key_exchange_modes',
  51: 'key_share',
  57: 'quic_transport_parameters',
  28: 'session_ticket',
  13: 'signature_algorithms',
};

const Map<int, String> supportedGroupsMap = {
  0x001d: "X25519",
  0x0017: "secp256r1",
};
