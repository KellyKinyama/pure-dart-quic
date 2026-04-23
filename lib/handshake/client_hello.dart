import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/equality.dart';
import 'package:hex/hex.dart';

import '../buffer.dart';
import 'keyshare.dart';
import 'tls_msg.dart';

// =============================================================
// ALPN helpers
// =============================================================

Uint8List buildAlpnExtensionData(List<String> protocols) {
  final listBody = BytesBuilder();

  for (final proto in protocols) {
    final bytes = Uint8List.fromList(utf8.encode(proto));
    if (bytes.isEmpty || bytes.length > 255) {
      throw ArgumentError('Invalid ALPN protocol length for "$proto"');
    }
    listBody.addByte(bytes.length);
    listBody.add(bytes);
  }

  final listBytes = listBody.toBytes();

  return Uint8List.fromList([
    (listBytes.length >> 8) & 0xFF,
    listBytes.length & 0xFF,
    ...listBytes,
  ]);
}

List<String> parseAlpnExtensionData(Uint8List data) {
  final buf = QuicBuffer(data: data);
  final protocols = <String>[];

  if (buf.remaining < 2) return protocols;

  final listLen = buf.pullUint16();
  final end = buf.readOffset + listLen;

  while (buf.readOffset < end && buf.remaining > 0) {
    final nameLen = buf.pullUint8();
    if (buf.remaining < nameLen) {
      throw StateError('ALPN extension truncated');
    }
    final nameBytes = buf.pullBytes(nameLen);
    protocols.add(utf8.decode(nameBytes, allowMalformed: true));
  }

  return protocols;
}

// =============================================================
// Generic TLS extensions parser
// =============================================================

List<TlsExtension> parseExtensions(QuicBuffer buffer) {
  if (buffer.remaining < 2) return [];

  final totalExtLen = buffer.pullUint16();
  final extensions = <TlsExtension>[];
  int extensionsRead = 0;

  while (extensionsRead < totalExtLen && buffer.remaining > 0) {
    final extType = buffer.pullUint16();
    final extLen = buffer.pullUint16();
    final extData = buffer.pullBytes(extLen);

    extensions.add(TlsExtension(type: extType, length: extLen, data: extData));

    extensionsRead += 4 + extLen;
  }

  return extensions;
}

// =============================================================
// ClientHello
// =============================================================

class ClientHello extends TlsHandshakeMessage {
  int legacyVersion;
  final Uint8List random;
  Uint8List sessionId;
  final List<int> cipherSuites;
  Uint8List compressionMethods;
  final List<TlsExtension> extensions;

  // Parsed extension variables
  String? sni;
  List<ParsedKeyShare>? keyShares;
  List<int>? supportedVersions;
  List<int>? supportedGroups;
  List<int>? signatureAlgorithms;
  List<String>? alpn;
  int? maxFragmentLength;
  Uint8List? padding;
  Uint8List? cookie;
  List<int>? pskKeyExchangeModes;
  Uint8List? preSharedKey;
  Uint8List? renegotiationInfo;
  Uint8List? quicTransportParametersRaw;

  final Uint8List rawData;

  ClientHello({
    required this.legacyVersion,
    required this.sessionId,
    required this.random,
    required this.cipherSuites,
    required this.compressionMethods,
    required this.extensions,
    required String type, // kept for compatibility with existing call sites
    this.sni,
    this.keyShares,
    this.supportedVersions,
    this.supportedGroups,
    this.signatureAlgorithms,
    this.alpn,
    this.maxFragmentLength,
    this.padding,
    this.cookie,
    this.pskKeyExchangeModes,
    this.preSharedKey,
    this.renegotiationInfo,
    this.quicTransportParametersRaw,
    required this.rawData,
  }) : super(0x01);

  // ------------------------------------------------------------
  // Convenience ALPN accessors
  // ------------------------------------------------------------

  List<String> get alpnProtocols => alpn ?? <String>[];

  set alpnProtocols(List<String> value) {
    alpn = value;
  }

  /// Replace or insert the ALPN extension (0x0010) based on [alpn].
  void upsertAlpnExtension() {
    final protocols = alpn ?? <String>[];

    // Remove ALPN extension if empty
    if (protocols.isEmpty) {
      extensions.removeWhere((e) => e.type == 0x0010);
      return;
    }

    final extData = buildAlpnExtensionData(protocols);
    final idx = extensions.indexWhere((e) => e.type == 0x0010);

    final ext = TlsExtension(
      type: 0x0010,
      length: extData.length,
      data: extData,
    );

    if (idx >= 0) {
      extensions[idx] = ext;
    } else {
      extensions.add(ext);
    }
  }

  @override
  String toString() {
    final suites = cipherSuites
        .map((s) => cipherSuitesMap[s] ?? 'Unknown (0x${s.toRadixString(16)})')
        .join(',\n    ');

    return '''
✅ Parsed ClientHello (Type 0x01):
- Legacy Version: 0x${legacyVersion.toRadixString(16)}
- Random: ${HEX.encode(random.sublist(0, 8))}...
- Session ID: ${HEX.encode(sessionId)}
- Cipher Suites:
    $suites
- Supported Versions: ${supportedVersions ?? []}
- Supported Groups: ${supportedGroups ?? []}
- Signature Algorithms: ${signatureAlgorithms ?? []}
- ALPN: ${alpn ?? []}
- Key Share: ${keyShares ?? []}
- Extensions Count: ${extensions.length}
''';
  }

  // ------------------------------------------------------------
  // Full handshake serialization (header + body)
  // ------------------------------------------------------------

  Uint8List serialize() {
    // Ensure ALPN extension reflects semantic field
    upsertAlpnExtension();

    final body = QuicBuffer();

    // 1. legacy_version
    body.pushUint16(legacyVersion);

    // 2. random
    body.pushBytes(random);

    // 3. legacy_session_id
    body.pushUint8(sessionId.length);
    body.pushBytes(sessionId);

    // 4. cipher_suites
    body.pushUint16(cipherSuites.length * 2);
    for (final suite in cipherSuites) {
      body.pushUint16(suite);
    }

    // 5. legacy_compression_methods
    body.pushUint8(compressionMethods.length);
    body.pushBytes(compressionMethods);

    // 6. extensions
    final extBuffer = QuicBuffer();
    for (final ext in extensions) {
      extBuffer.pushUint16(ext.type);
      extBuffer.pushUint16(ext.data.length);
      extBuffer.pushBytes(ext.data);
    }

    final extBytes = extBuffer.toBytes();
    body.pushUint16(extBytes.length);
    body.pushBytes(extBytes);

    final bodyBytes = body.toBytes();

    // 7. Handshake header
    final header = Uint8List(4);
    header[0] = 0x01; // ClientHello
    header[1] = (bodyBytes.length >> 16) & 0xFF;
    header[2] = (bodyBytes.length >> 8) & 0xFF;
    header[3] = bodyBytes.length & 0xFF;

    return Uint8List.fromList([...header, ...bodyBytes]);
  }

  // ------------------------------------------------------------
  // Parse ClientHello body (without handshake header)
  // ------------------------------------------------------------

  static ClientHello parse_tls_client_hello(Uint8List body) {
    final view = body;
    int ptr = 0;

    final legacyVersion = (view[ptr++] << 8) | view[ptr++];
    final random = view.sublist(ptr, ptr + 32);
    ptr += 32;

    final sessionIdLen = view[ptr++];
    final sessionId = view.sublist(ptr, ptr + sessionIdLen);
    ptr += sessionIdLen;

    final cipherSuitesLen = (view[ptr++] << 8) | view[ptr++];
    final cipherSuites = <int>[];
    for (int i = 0; i < cipherSuitesLen; i += 2) {
      final code = (view[ptr++] << 8) | view[ptr++];
      cipherSuites.add(code);
    }

    final compressionMethodsLen = view[ptr++];
    final compressionMethods = view.sublist(ptr, ptr + compressionMethodsLen);
    ptr += compressionMethodsLen;

    final extensionsLen = (view[ptr++] << 8) | view[ptr++];
    final extensions = <TlsExtension>[];
    final extEnd = ptr + extensionsLen;

    while (ptr < extEnd) {
      final extType = (view[ptr++] << 8) | view[ptr++];
      final extLen = (view[ptr++] << 8) | view[ptr++];
      final extData = view.sublist(ptr, ptr + extLen);
      ptr += extLen;

      extensions.add(
        TlsExtension(type: extType, length: extLen, data: extData),
      );
    }

    // ----------------------------------------------------------
    // Semantic decoding
    // ----------------------------------------------------------
    String? sni;
    final keyShares = <ParsedKeyShare>[];
    final supportedGroups = <int>[];
    final supportedVersions = <int>[];
    final signatureAlgorithms = <int>[];
    final alpnProtocols = <String>[];
    Uint8List? cookie;
    List<int>? pskKeyExchangeModes;
    Uint8List? quicTransportParametersRaw;

    for (final ext in extensions) {
      final buf = QuicBuffer(data: ext.data);

      switch (ext.type) {
        // ------------------------------------------------------
        // server_name (0x0000)
        // ------------------------------------------------------
        case 0x0000:
          if (buf.remaining < 2) break;
          final listLen = buf.pullUint16();
          final end = buf.readOffset + listLen;

          while (buf.readOffset < end && buf.remaining > 0) {
            final nameType = buf.pullUint8();
            final nameLen = buf.pullUint16();
            final nameBytes = buf.pullBytes(nameLen);

            if (nameType == 0x00) {
              sni = utf8.decode(nameBytes, allowMalformed: true);
            }
          }
          break;

        // ------------------------------------------------------
        // supported_groups (0x000a)
        // ------------------------------------------------------
        case 0x000a:
          final len = buf.pullUint16();
          for (int i = 0; i < len; i += 2) {
            supportedGroups.add(buf.pullUint16());
          }
          break;

        // ------------------------------------------------------
        // signature_algorithms (0x000d)
        // ------------------------------------------------------
        case 0x000d:
          final len = buf.pullUint16();
          for (int i = 0; i < len; i += 2) {
            signatureAlgorithms.add(buf.pullUint16());
          }
          break;

        // ------------------------------------------------------
        // ALPN (0x0010)
        // ------------------------------------------------------
        case 0x0010:
          alpnProtocols.addAll(parseAlpnExtensionData(ext.data));
          break;

        // ------------------------------------------------------
        // cookie (0x002c)
        // ------------------------------------------------------
        case 0x002c:
          if (buf.remaining < 2) break;
          final len = buf.pullUint16();
          cookie = buf.pullBytes(len);
          break;

        // ------------------------------------------------------
        // psk_key_exchange_modes (0x002d)
        // ------------------------------------------------------
        case 0x002d:
          if (buf.remaining < 1) break;
          final len = buf.pullUint8();
          pskKeyExchangeModes = <int>[];
          for (int i = 0; i < len; i++) {
            pskKeyExchangeModes.add(buf.pullUint8());
          }
          break;

        // ------------------------------------------------------
        // supported_versions (0x002b)
        // ------------------------------------------------------
        case 0x002b:
          final len = buf.pullUint8();
          for (int i = 0; i < len; i += 2) {
            supportedVersions.add(buf.pullUint16());
          }
          break;

        // ------------------------------------------------------
        // key_share (0x0033)
        // ------------------------------------------------------
        case 0x0033:
          final listLen = buf.pullUint16();
          final end = buf.readOffset + listLen;

          while (buf.readOffset < end) {
            final group = buf.pullUint16();
            final keyLen = buf.pullUint16();
            final key = buf.pullBytes(keyLen);
            keyShares.add(ParsedKeyShare(group, key));
          }
          break;

        // ------------------------------------------------------
        // QUIC transport parameters (0x0039)
        // ------------------------------------------------------
        case 0x0039:
          quicTransportParametersRaw = ext.data;
          break;

        default:
          break;
      }
    }

    return ClientHello(
      type: 'client_hello',
      legacyVersion: legacyVersion,
      random: random,
      sessionId: sessionId,
      cipherSuites: cipherSuites,
      compressionMethods: compressionMethods,
      extensions: extensions,
      rawData: body,
      sni: sni,
      keyShares: keyShares,
      supportedGroups: supportedGroups,
      supportedVersions: supportedVersions,
      signatureAlgorithms: signatureAlgorithms,
      alpn: alpnProtocols,
      cookie: cookie,
      pskKeyExchangeModes: pskKeyExchangeModes,
      quicTransportParametersRaw: quicTransportParametersRaw,
    );
  }

  // ------------------------------------------------------------
  // Body-only builder (without handshake header)
  // ------------------------------------------------------------

  Uint8List build_tls_client_hello() {
    upsertAlpnExtension();

    final buffer = QuicBuffer();

    // Legacy Version
    buffer.pushUint16(legacyVersion);

    // Random
    buffer.pushBytes(random);

    // Session ID
    buffer.pushUint8(sessionId.length);
    buffer.pushBytes(sessionId);

    // Cipher Suites (length in bytes)
    buffer.pushUint16(cipherSuites.length * 2);
    for (final cipherSuite in cipherSuites) {
      buffer.pushUint16(cipherSuite);
    }

    // Compression Methods
    buffer.pushUint8(compressionMethods.length);
    buffer.pushBytes(compressionMethods);

    // Extensions
    final extBuffer = QuicBuffer();
    for (final extension in extensions) {
      extBuffer.pushUint16(extension.type);
      extBuffer.pushUint16(extension.data.length);
      extBuffer.pushBytes(extension.data);
    }

    final extBytes = extBuffer.toBytes();
    buffer.pushUint16(extBytes.length);
    buffer.pushBytes(extBytes);

    return buffer.toBytes();
  }

  // ------------------------------------------------------------
  // Full handshake builder (same as serialize)
  // ------------------------------------------------------------

  Uint8List build_tls_client_hello2() {
    return serialize();
  }

  // ------------------------------------------------------------
  // Instance helper
  // ------------------------------------------------------------

  List<TlsExtension> parseExtensions(QuicBuffer buffer) {
    return parseExtensionsTop(buffer);
  }
}

// =============================================================
// Standalone helpers
// =============================================================

ClientHello parseClientHelloBody(QuicBuffer buffer) {
  final start = buffer.readOffset;
  final body = buffer.pullBytes(buffer.remaining);

  final ch = ClientHello.parse_tls_client_hello(body);

  // rawData should be exact body bytes
  return ClientHello(
    type: 'client_hello',
    legacyVersion: ch.legacyVersion,
    random: ch.random,
    sessionId: ch.sessionId,
    cipherSuites: ch.cipherSuites,
    compressionMethods: ch.compressionMethods,
    extensions: ch.extensions,
    rawData: buffer.data.sublist(start, start + body.length),
    sni: ch.sni,
    keyShares: ch.keyShares,
    supportedVersions: ch.supportedVersions,
    supportedGroups: ch.supportedGroups,
    signatureAlgorithms: ch.signatureAlgorithms,
    alpn: ch.alpn,
    maxFragmentLength: ch.maxFragmentLength,
    padding: ch.padding,
    cookie: ch.cookie,
    pskKeyExchangeModes: ch.pskKeyExchangeModes,
    preSharedKey: ch.preSharedKey,
    renegotiationInfo: ch.renegotiationInfo,
    quicTransportParametersRaw: ch.quicTransportParametersRaw,
  );
}

List<TlsExtension> parseExtensionsTop(QuicBuffer buffer) {
  if (buffer.remaining < 2) return [];
  final totalExtLen = buffer.pullUint16();
  final extensions = <TlsExtension>[];
  int extensionsRead = 0;

  while (extensionsRead < totalExtLen && buffer.remaining > 0) {
    final extType = buffer.pullUint16();
    final extLen = buffer.pullUint16();
    final extData = buffer.pullBytes(extLen);

    extensions.add(TlsExtension(type: extType, length: extLen, data: extData));

    extensionsRead += 4 + extLen;
  }

  return extensions;
}

// =============================================================
// Demo / round-trip test
// =============================================================

final clientHello = Uint8List.fromList(
  HEX.decode(
    "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64"
        .replaceAll(" ", ""),
  ),
);

void main() {
  // ==========================================================
  // 1️⃣ Raw TLS ClientHello (handshake header + body)
  // ==========================================================
  final clientHelloWire = Uint8List.fromList(
    HEX.decode(
      "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64"
          .replaceAll(" ", ""),
    ),
  );

  print("✅ ClientHello wire length = ${clientHelloWire.length}");
  print("Handshake type = 0x${clientHelloWire[0].toRadixString(16)}");

  // ==========================================================
  // 2️⃣ Parse ClientHello (strip handshake header)
  // ==========================================================
  final parsed = ClientHello.parse_tls_client_hello(clientHelloWire.sublist(4));

  print(parsed);

  // ✅ sanity checks
  if (parsed.legacyVersion != 0x0303) {
    throw StateError(
      "Invalid legacy_version: expected 0x0303, "
      "got 0x${parsed.legacyVersion.toRadixString(16)}",
    );
  }

  if (!parsed.cipherSuites.contains(0x1301)) {
    throw StateError(
      "ClientHello does not advertise TLS_AES_128_GCM_SHA256 (0x1301)",
    );
  }

  if (parsed.keyShares == null || parsed.keyShares!.isEmpty) {
    throw StateError("ClientHello contains no key_share extension");
  }

  // final x25519Share = parsed.keyShares!.firstWhere(
  //   (ks) => ks.group == 0x001d,
  //   orElse: () => throw StateError(
  //     "ClientHello does not contain an X25519 (0x001d) key_share",
  //   ),
  // );

  // ==========================================================
  // 3️⃣ Re‑serialize ClientHello
  // ==========================================================
  final rebuilt = parsed.serialize();

  print("✅ Rebuilt ClientHello length = ${rebuilt.length}");

  // ==========================================================
  // 4️⃣ Byte‑for‑byte equality check
  // ==========================================================
  final eq = const ListEquality<int>().equals(clientHelloWire, rebuilt);

  if (!eq) {
    print("❌ MISMATCH!");
    print("Original:");
    print(HEX.encode(clientHelloWire));
    print("Rebuilt:");
    print(HEX.encode(rebuilt));
    throw StateError("ClientHello round‑trip mismatch");
  }

  print("✅ ClientHello parse ⇄ build round‑trip OK");
}

// void main() {
//   final originalWire = Uint8List.fromList(
//     HEX.decode(
//       "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64"
//           .replaceAll(" ", ""),
//     ),
//   );

//   Uint8List current = originalWire;

//   const iterations = 10;

//   for (int i = 0; i < iterations; i++) {
//     // --------------------------------------------------
//     // 1. Parse (strip handshake header)
//     // --------------------------------------------------
//     if (current.length < 4 || current[0] != 0x01) {
//       throw StateError("Iteration $i: not a ClientHello handshake");
//     }

//     final parsed = ClientHello.parse_tls_client_hello(current.sublist(4));

//     // --------------------------------------------------
//     // 2. Validate parsed structure explicitly
//     // --------------------------------------------------
//     if (parsed.legacyVersion != 0x0303) {
//       throw StateError("Iteration $i: legacy_version mismatch");
//     }

//     if (!parsed.cipherSuites.contains(0x1301)) {
//       throw StateError("Iteration $i: missing TLS_AES_128_GCM_SHA256");
//     }

//     if (parsed.keyShares == null || parsed.keyShares!.isEmpty) {
//       throw StateError("Iteration $i: key_share missing");
//     }

//     final hasX25519 = parsed.keyShares!.any((ks) => ks.group == 0x001d);

//     if (!hasX25519) {
//       throw StateError("Iteration $i: X25519 key_share missing");
//     }

//     // --------------------------------------------------
//     // 3. Rebuild
//     // --------------------------------------------------
//     final rebuilt = parsed.serialize();

//     // --------------------------------------------------
//     // 4. Byte‑for‑byte compare
//     // --------------------------------------------------
//     if (rebuilt.length != current.length) {
//       throw StateError(
//         "Iteration $i: length mismatch "
//         "${rebuilt.length} != ${current.length}",
//       );
//     }

//     for (int j = 0; j < rebuilt.length; j++) {
//       if (rebuilt[j] != current[j]) {
//         throw StateError(
//           "Iteration $i: byte mismatch at offset $j "
//           "(0x${current[j].toRadixString(16)} != "
//           "0x${rebuilt[j].toRadixString(16)})",
//         );
//       }
//     }

//     print("✅ Iteration $i OK");

//     // Feed rebuilt bytes into next round
//     current = rebuilt;
//   }

//   print("✅ ClientHello stable after $iterations parse ⇄ build cycles");
// }
