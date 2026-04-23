import 'dart:typed_data';
import 'package:hex/hex.dart';
// import 'package:lemon_tls/quic/quic_learn/client/quic_session.dart';

import '../buffer.dart';
// import '../quic_learn/client/quic_session3.dart';
// import '../constants.dart';
// import '../quic_learn/server/constants.dart';
import '../connection/client/quic_session3.dart';
import '../constants.dart';
import 'client_hello.dart';
import 'server_hello.dart';
import 'encrypted_extensions.dart';
import 'certificate.dart';
import 'certificate_verify.dart';
import 'finished.dart';
import 'tls_msg.dart';

// abstract class TlsHandshakeMessage {
//   final int msgType;
//   String get typeName => handshakeTypeMap[msgType] ?? 'Unknown';
//   TlsHandshakeMessage(this.msgType);
// }

// class UnknownHandshakeMessage extends TlsHandshakeMessage {
//   final Uint8List body;
//   UnknownHandshakeMessage(int msgType, this.body) : super(msgType);

//   @override
//   String toString() =>
//       'ℹ️ Parsed UnknownHandshake(type: $msgType, len: ${body.length})';
// }

List<TlsHandshakeMessage> parseTlsMessages(
  Uint8List cryptoData, {
  QuicSession? quicSession,
}) {
  final buffer = QuicBuffer(data: cryptoData);
  final messages = <TlsHandshakeMessage>[];

  while (buffer.remaining > 0) {
    final msgType = buffer.pullUint8();
    final length = buffer.pullUint24();

    print("handshake length: $length");

    final body = buffer.pullBytes(length);
    final bodyBuf = QuicBuffer(data: body);

    switch (msgType) {
      case 0x01: // ClientHello
        final ch = parseClientHelloBody(bodyBuf);
        print("Serialized: ${HEX.encode(ch.build_tls_client_hello())}");
        messages.add(ch);
        break;

      case 0x02: // ServerHello
        print("✅ ServerHello received (${length} bytes)");
        final sh = ServerHello.parse(bodyBuf);
        if (quicSession != null) {
          quicSession.encryptionLevel = EncryptionLevel.handshake;
          quicSession.receivedServello = sh;
        }
        messages.add(sh);
        break;

      case 0x08: // Encrypted Extensions
        print("✅ EncryptedExtensions received (${length} bytes)");
        final ee = EncryptedExtensions.parse(bodyBuf);
        print("ee: $ee");
        messages.add(ee);
        break;

      case 0x0B: // Certificate
        print("✅ Certificate received (${length} bytes)");
        final cert = CertificateMessage.parse(bodyBuf);
        messages.add(cert);
        break;

      case 0x0F: // CertificateVerify
        print("✅ CertificateVerify received (${length} bytes)");
        final cv = CertificateVerify.parse(bodyBuf);
        messages.add(cv);
        break;

      case 0x14: // Finished
        print("✅ Finished received (${length} bytes)");
        final fin = FinishedMessage.parse(bodyBuf);
        messages.add(fin);

        // if (quicSession != null) {
        // quicSession.deriveApplicationSecrets();
        // quicSession.tlsHandshakeMessages.add(fin);
        // }

        break;

      default:
        print("⚠️ Unknown handshake message: type=$msgType len=$length");
        messages.add(
          UnknownHandshakeMessage(msgType, bodyBuf.pullBytes(bodyBuf.length)),
        );
        break;
    }
  }

  return messages;
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

void main() {}
