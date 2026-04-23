// server_hello.dart
import 'dart:typed_data';
import 'package:hex/hex.dart';

import '../buffer.dart';
import '../constants.dart';
// import '../quic_learn/server/constants.dart';
// import '../quic_learn/server/quic_server_session.dart';
import 'client_hello.dart';
import 'tls_msg.dart';
import 'keyshare.dart'; // for ParsedKeyShare

// import 'package:x25519/x25519.dart' as ecdhe;

class ServerHello extends TlsHandshakeMessage {
  final int legacyVersion;
  final Uint8List random;
  final Uint8List sessionId;
  final int cipherSuite;
  final int compressionMethod;
  final Uint8List? rawBytes;

  // Parsed extensions
  final int? selectedVersion; // from supported_versions
  final ParsedKeyShare? keyShareEntry; // from key_share
  final Map<int, Uint8List> extensionsRaw; // stores all extension bodies

  ServerHello({
    required this.legacyVersion,
    required this.random,
    required this.sessionId,
    required this.cipherSuite,
    required this.compressionMethod,
    required this.extensionsRaw,
    required int msgType, // ALWAYS 0x02
    this.keyShareEntry,
    this.selectedVersion,
    this.rawBytes,
  }) : super(msgType);

  // ============================================================
  // ✅ PARSE — matches your JS & Dart ServerHello builder
  // ============================================================
  static ServerHello parse(QuicBuffer buf) {
    final legacyVersion = buf.pullUint16();
    final random = buf.pullBytes(32);

    final sidLen = buf.pullUint8();
    final sessionId = buf.pullBytes(sidLen);

    final cipherSuite = buf.pullUint16();

    final compression = buf.pullUint8();

    // ----------------------------
    // Parse extensions block
    // ----------------------------
    final extLen = buf.pullUint16();
    final extEnd = buf.readOffset + extLen;

    int? version;
    ParsedKeyShare? keyShare;
    final raw = <int, Uint8List>{};

    while (buf.readOffset < extEnd) {
      final extType = buf.pullUint16();
      final eLen = buf.pullUint16();
      final extData = buf.pullBytes(eLen);

      raw[extType] = extData;

      final extBuf = QuicBuffer(data: extData);

      switch (extType) {
        // supported_versions
        case 0x002B:
          if (eLen == 2) version = extBuf.pullUint16(); // should be 0x0304
          break;

        // key_share
        case 0x0033:
          final group = extBuf.pullUint16();
          final keyLen = extBuf.pullUint16();
          final key = extBuf.pullBytes(keyLen);
          keyShare = ParsedKeyShare(group, key);
          break;

        default:
          // leave extension data in raw[]
          break;
      }
    }

    return ServerHello(
      legacyVersion: legacyVersion,
      random: random,
      sessionId: sessionId,
      cipherSuite: cipherSuite,
      compressionMethod: compression,
      extensionsRaw: raw,
      keyShareEntry: keyShare,
      selectedVersion: version,
      msgType: 0x02,
      rawBytes: buf.data.sublist(0, buf.readOffset),
    );
  }

  // ============================================================
  // ✅ Debug Print
  // ============================================================
  @override
  String toString() {
    final ks = keyShareEntry != null
        ? "group=0x${keyShareEntry!.group.toRadixString(16)}, key=${HEX.encode(keyShareEntry!.pub)}"
        : "null";

    final ver = selectedVersion != null
        ? "0x${selectedVersion!.toRadixString(16)}"
        : "null";

    return '''
✅ Parsed ServerHello:
  legacy_version: 0x${legacyVersion.toRadixString(16)}
  random: ${HEX.encode(random.sublist(0, 8))}...
  session_id: ${HEX.encode(sessionId)}
  cipher_suite: 0x${cipherSuite.toRadixString(16)}
  compression: $compressionMethod
  selected_version: $ver
  key_share: $ks
''';
  }
}

Uint8List buildServerHello({
  required Uint8List serverRandom,
  required Uint8List publicKey,
  required Uint8List sessionId,
  required int cipherSuite,
  required int group,
}) {
  final out = BytesBuilder();

  // --------------------------------------------------
  // Handshake body
  // --------------------------------------------------
  final body = BytesBuilder();

  // legacy_version = 0x0303
  body.add([0x03, 0x03]);

  // random (32 bytes)
  body.add(serverRandom);

  // legacy_session_id_echo
  body.addByte(sessionId.length & 0xff);
  body.add(sessionId);

  // cipher_suite
  body.add([(cipherSuite >> 8) & 0xff, cipherSuite & 0xff]);

  // legacy_compression_method = 0x00
  body.addByte(0x00);

  // --------------------------------------------------
  // Extensions
  // --------------------------------------------------
  final extensions = BytesBuilder();

  // supported_versions extension
  // type = 0x002b, len = 0x0002, value = 0x0304
  extensions.add([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

  // key_share extension
  final keyShareBody = BytesBuilder()
    ..add([(group >> 8) & 0xff, group & 0xff])
    ..add([(publicKey.length >> 8) & 0xff, publicKey.length & 0xff])
    ..add(publicKey);

  final keyShareBytes = keyShareBody.toBytes();

  extensions.add([
    0x00, 0x33, // extension type
    (keyShareBytes.length >> 8) & 0xff,
    keyShareBytes.length & 0xff,
    ...keyShareBytes,
  ]);

  final extBytes = extensions.toBytes();

  // extensions length
  body.add([(extBytes.length >> 8) & 0xff, extBytes.length & 0xff]);

  body.add(extBytes);

  final bodyBytes = body.toBytes();

  // --------------------------------------------------
  // Handshake wrapper
  // type = 0x02 (ServerHello)
  // length = uint24
  // --------------------------------------------------
  out.addByte(0x02);
  out.add([
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
  ]);
  out.add(bodyBytes);

  return out.toBytes();
}

Uint8List buildServerHelloFromKeyPair({
  required KeyPair keyPair,
  required Uint8List serverRandom,
  required int cipherSuite,
  Uint8List? sessionId,
}) {
  return buildServerHello(
    serverRandom: serverRandom,
    publicKey: keyPair.publicKeyBytes,
    sessionId: sessionId ?? Uint8List(0),
    cipherSuite: cipherSuite,
    group: 0x001d, // X25519
  );
}

class ServerHelloResult {
  final Uint8List bytes;
  final ParsedKeyShare selectedKeyShare;
  final int cipherSuite;

  ServerHelloResult({
    required this.bytes,
    required this.selectedKeyShare,
    required this.cipherSuite,
  });
}

ServerHelloResult buildServerHelloFromClientHello({
  required ClientHello ch,
  required KeyPair serverKeyPair,
}) {
  // ------------------------------------------
  // 1. Select cipher suite (TLS_AES_128_GCM_SHA256)
  // ------------------------------------------
  const supportedCipherSuites = [
    0x1301, // TLS_AES_128_GCM_SHA256
  ];

  final cipherSuite = supportedCipherSuites.firstWhere(
    (cs) => ch.cipherSuites.contains(cs),
    orElse: () => throw StateError("No supported cipher suite"),
  );

  // ------------------------------------------
  // 2. Select key share (X25519)
  // ------------------------------------------
  final keyShare = ch.keyShares!.firstWhere(
    (ks) => ks.group == 0x001d,
    orElse: () => throw StateError("No X25519 key share"),
  );

  // ------------------------------------------
  // 3. Build ServerHello
  // ------------------------------------------
  final serverRandom = Uint8List(32);
  for (int i = 0; i < 32; i++) {
    serverRandom[i] = DateTime.now().microsecondsSinceEpoch >> (i % 8);
  }

  final serverHelloBytes = buildServerHello(
    serverRandom: serverRandom,
    publicKey: serverKeyPair.publicKeyBytes,
    sessionId: Uint8List(0),
    cipherSuite: cipherSuite,
    group: keyShare.group,
  );

  return ServerHelloResult(
    bytes: serverHelloBytes,
    selectedKeyShare: keyShare,
    cipherSuite: cipherSuite,
  );
}

// void main() {
//   // ==========================================================
//   // 1️⃣ Raw QUIC Initial payload containing ClientHello
//   // ==========================================================
//   final udp1ClientHello = Uint8List.fromList(
//     HEX.decode(
//       "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64"
//           .replaceAll(" ", ""),
//     ),
//   );

//   print("✅ Raw UDP payload length = ${udp1ClientHello.length}");

//   // ==========================================================
//   // 2️⃣ Extract TLS Handshake (skip QUIC header)
//   //    Your logs show CRYPTO frame starts at offset 0x40
//   // ==========================================================

//   print("✅ TLS handshake length = ${udp1ClientHello.length}");
//   print("TLS handshake type = 0x${udp1ClientHello[0].toRadixString(16)}");

//   // ==========================================================
//   // 2️⃣ Parse ClientHello
//   // ==========================================================

//   // Skip handshake header (1 + 3 bytes)
//   final clientHello = ClientHello.parse_tls_client_hello(
//     udp1ClientHello.sublist(4),
//   );

//   print(clientHello);

//   // ==========================================================
//   // 4️⃣ Create server crypto
//   // ==========================================================
//   final serverKeyPair = KeyPair.generate();

//   // ==========================================================
//   // 5️⃣ Select cipher suite
//   // ==========================================================
//   const supportedCipherSuites = [0x1301]; // TLS_AES_128_GCM_SHA256

//   final cipherSuite = supportedCipherSuites.firstWhere(
//     (cs) => clientHello.cipherSuites.contains(cs),
//     orElse: () => throw StateError("No common cipher suite"),
//   );

//   // ==========================================================
//   // 6️⃣ Select X25519 key share
//   // ==========================================================
//   final keyShare = clientHello.keyShares!.firstWhere(
//     (ks) => ks.group == 0x001d,
//     orElse: () => throw StateError("No X25519 key share"),
//   );

//   print("✅ Selected key share: group=0x${keyShare.group.toRadixString(16)}");

//   // ==========================================================
//   // 7️⃣ Build ServerHello
//   // ==========================================================
//   final serverRandom = Uint8List(32);
//   for (int i = 0; i < 32; i++) {
//     serverRandom[i] = i;
//   }

//   final serverHelloBytes = buildServerHello(
//     serverRandom: serverRandom,
//     publicKey: serverKeyPair.publicKeyBytes,
//     sessionId: Uint8List(0),
//     cipherSuite: cipherSuite,
//     group: keyShare.group,
//   );

//   print("✅ Built ServerHello (${serverHelloBytes.length} bytes)");
//   print("ServerHello HEX:");
//   print(HEX.encode(serverHelloBytes));

//   // ==========================================================
//   // 8️⃣ Parse ServerHello back (round-trip test)
//   // ==========================================================
//   final shBuf = QuicBuffer(data: serverHelloBytes.sublist(4));
//   final parsedServerHello = ServerHello.parse(shBuf);

//   print(parsedServerHello);

//   // ==========================================================
//   // 9️⃣ Compute shared secret (ECDHE)
//   // ==========================================================
//   final sharedSecret = ecdhe.X25519(
//     serverKeyPair.privateKeyBytes,
//     keyShare.pub,
//   );

//   print("✅ Shared secret:");
//   print(HEX.encode(sharedSecret));
// }

void main() {
  // ==========================================================
  // 1️⃣ Parse ClientHello (already validated earlier)
  // ==========================================================
  final clientHelloWire = Uint8List.fromList(
    HEX.decode(
      "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64"
          .replaceAll(" ", ""),
    ),
  );

  final clientHello = ClientHello.parse_tls_client_hello(
    clientHelloWire.sublist(4),
  );

  final keyShare = clientHello.keyShares!.firstWhere(
    (ks) => ks.group == 0x001d,
    orElse: () => throw StateError("Missing X25519 key share"),
  );

  // ==========================================================
  // 2️⃣ Create fixed server crypto (ONE TIME)
  // ==========================================================
  final serverKeyPair = KeyPair.generate();

  final serverRandom = Uint8List(32);
  for (int i = 0; i < 32; i++) {
    serverRandom[i] = i;
  }

  // ==========================================================
  // 3️⃣ Build initial ServerHello ONCE
  // ==========================================================
  Uint8List current = buildServerHello(
    serverRandom: serverRandom,
    publicKey: serverKeyPair.publicKeyBytes,
    sessionId: Uint8List(0),
    cipherSuite: 0x1301,
    group: keyShare.group,
  );

  print("✅ Initial ServerHello length = ${current.length}");

  const iterations = 10;

  for (int i = 0; i < iterations; i++) {
    // --------------------------------------------------
    // 4️⃣ Parse ServerHello (skip handshake header)
    // --------------------------------------------------
    if (current.length < 4 || current[0] != 0x02) {
      throw StateError("Iteration $i: not a ServerHello handshake");
    }

    final buf = QuicBuffer(data: current.sublist(4));
    final parsed = ServerHello.parse(buf);

    // --------------------------------------------------
    // 5️⃣ Validate parsed ServerHello
    // --------------------------------------------------
    if (parsed.legacyVersion != 0x0303) {
      throw StateError("Iteration $i: invalid legacy_version");
    }

    if (parsed.cipherSuite != 0x1301) {
      throw StateError("Iteration $i: cipher_suite mismatch");
    }

    if (parsed.keyShareEntry == null || parsed.keyShareEntry!.group != 0x001d) {
      throw StateError("Iteration $i: key_share mismatch");
    }

    // --------------------------------------------------
    // 6️⃣ Rebuild ServerHello from parsed fields
    // --------------------------------------------------
    final rebuilt = buildServerHello(
      serverRandom: parsed.random,
      publicKey: parsed.keyShareEntry!.pub,
      sessionId: parsed.sessionId,
      cipherSuite: parsed.cipherSuite,
      group: parsed.keyShareEntry!.group,
    );

    // --------------------------------------------------
    // 7️⃣ Byte‑for‑byte compare
    // --------------------------------------------------
    if (rebuilt.length != current.length) {
      throw StateError(
        "Iteration $i: length mismatch "
        "${rebuilt.length} != ${current.length}",
      );
    }

    for (int j = 0; j < rebuilt.length; j++) {
      if (rebuilt[j] != current[j]) {
        throw StateError(
          "Iteration $i: byte mismatch at offset $j "
          "(0x${current[j].toRadixString(16)} != "
          "0x${rebuilt[j].toRadixString(16)})",
        );
      }
    }

    print("✅ Iteration $i OK");

    current = rebuilt;
  }

  print("✅ ServerHello stable after $iterations parse ⇄ build cycles");
}
