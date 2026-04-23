import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';

import '../../buffer.dart';
import '../../cipher/cert_utils.dart';
import '../../cipher/fingerprint.dart';
import '../../cipher/hash.dart';
import '../../cipher/hkdf.dart';
import '../../cipher/x25519.dart';
import '../../constants.dart';
import '../../frames/quic_ack.dart';
import '../../h3/h3.dart';
import '../../handshake/client_hello.dart';
import '../../handshake/server_hello.dart';
import '../../handshake/tls_server_builder.dart';
// import '../../hash.dart';
// import '../../hkdf.dart';
import '../../packet/quic_packet.dart';
// import '../../quic_ack.dart';
import '../../utils.dart';
// import '../cert_utils.dart';
// import '../constants.dart';
// import '../fingerprint.dart';
// import '../h31.dart';
// import 'constants.dart';

class QuicServerSession {
  final RawDatagramSocket socket;
  late final InternetAddress peerAddress;
  late final int peerPort;

  EncryptionLevel encryptionLevel = EncryptionLevel.initial;

  QuicKeys? initialRead, initialWrite;
  QuicKeys? handshakeRead, handshakeWrite;
  QuicKeys? appRead, appWrite;

  late Uint8List derivedSecret;
  late Uint8List clientHsTrafficSecret;
  late Uint8List serverHsTrafficSecret;

  Uint8List? serverFinishedBytes;
  Uint8List? transcriptThroughServerFinishedBytes;

  late Uint8List encryptedExtensions;
  late Uint8List certificate;
  late Uint8List certificateVerify;

  final Map<EncryptionLevel, PacketNumberSpace> recvPnSpaces = {
    EncryptionLevel.initial: PacketNumberSpace(),
    EncryptionLevel.handshake: PacketNumberSpace(),
    EncryptionLevel.application: PacketNumberSpace(),
  };

  final Map<EncryptionLevel, int> nextSendPn = {
    EncryptionLevel.initial: 0,
    EncryptionLevel.handshake: 1,
    EncryptionLevel.application: 0,
  };

  final Map<EncryptionLevel, AckState> ackStates = {
    EncryptionLevel.initial: AckState(),
    EncryptionLevel.handshake: AckState(),
    EncryptionLevel.application: AckState(),
  };

  final Map<EncryptionLevel, Map<int, Uint8List>> cryptoChunksByLevel = {
    EncryptionLevel.initial: <int, Uint8List>{},
    EncryptionLevel.handshake: <int, Uint8List>{},
    EncryptionLevel.application: <int, Uint8List>{},
  };

  final Map<EncryptionLevel, int> cryptoReadOffsetByLevel = {
    EncryptionLevel.initial: 0,
    EncryptionLevel.handshake: 0,
    EncryptionLevel.application: 0,
  };

  final Map<EncryptionLevel, BytesBuilder> receivedHandshakeByLevel = {
    EncryptionLevel.initial: BytesBuilder(),
    EncryptionLevel.handshake: BytesBuilder(),
    EncryptionLevel.application: BytesBuilder(),
  };

  bool initialKeysReady = false;
  bool handshakeKeysReady = false;
  bool serverFlightSent = false;
  bool clientFinishedVerified = false;
  bool applicationSecretsDerived = false;
  bool handshakeComplete = false;
  bool serverHandshakeFinished = false;

  EcdsaCert serverCert = generateSelfSignedCertificate();
  KeyPair keyPair = KeyPair.generate();

  late ClientHello ch;

  Uint8List? fullClientHelloBytes;
  Uint8List? serverHelloBytes;
  Uint8List? clientHelloMsg;
  Uint8List? serverHelloMsg;

  late Uint8List peerScid;
  late Uint8List localCid;
  late Uint8List clientOrigDcid;

  late Uint8List handshakeSecret;

  late final Uint8List serverRandom = Uint8List.fromList(
    List.generate(32, (_) => math.Random.secure().nextInt(256)),
  );

  // ============================================================
  // HTTP/3 + WebTransport state
  // ============================================================

  final Http3State h3 = Http3State();
  int nextServerBidiStreamId = 1;
  int nextServerUniStreamId = 3;

  QuicServerSession({required this.socket}) {
    print("Server certificate hash: ${fingerprint(serverCert.fingerPrint)}");
    localCid = _randomCid(8);
  }

  Uint8List _randomCid([int len = 8]) {
    final rnd = math.Random.secure();
    return Uint8List.fromList(List.generate(len, (_) => rnd.nextInt(256)));
  }

  // ============================================================
  // Public entry point
  // ============================================================

  // void handleDatagram(Uint8List pkt) {
  //   final packetLevel = detectPacketLevel(pkt);
  //   print("📥 Server received packet level=$packetLevel len=${pkt.length}");

  //   if (!initialKeysReady) {
  //     if (packetLevel != EncryptionLevel.initial) {
  //       print("ℹ️ Ignoring non-Initial packet before initial keys are ready");
  //       return;
  //     }
  //     _deriveInitialKeysFromFirstPacket(pkt);
  //   }

  //   if (packetLevel == EncryptionLevel.handshake && handshakeRead == null) {
  //     print("ℹ️ Ignoring early Handshake packet (handshake keys not ready)");
  //     return;
  //   }

  //   if (packetLevel == EncryptionLevel.application &&
  //       !applicationSecretsDerived) {
  //     print("ℹ️ Ignoring early Application packet (1-RTT keys not ready)");
  //     return;
  //   }

  //   final decrypted = decryptPacket(pkt, packetLevel);
  //   final ackEliciting = _parsePayload(decrypted.plaintext!, packetLevel);
  //   _onDecryptedPacket(decrypted, packetLevel, ackEliciting);
  // }

  // ============================================================
  // Level detection
  // ============================================================

  EncryptionLevel detectPacketLevel(Uint8List pkt) {
    final firstByte = pkt[0];
    final isLong = (firstByte & 0x80) != 0;

    if (!isLong) {
      return EncryptionLevel.application;
    }

    final typeBits = (firstByte >> 4) & 0x03;
    switch (typeBits) {
      case 0x00:
        return EncryptionLevel.initial;
      case 0x02:
        return EncryptionLevel.handshake;
      default:
        throw StateError(
          "Unsupported long-header packet type: 0x${typeBits.toRadixString(16)}",
        );
    }
  }

  // ============================================================
  // Initial secrets
  // ============================================================

  void _deriveInitialKeysFromFirstPacket(Uint8List pkt) {
    final cids = _extractLongHeaderCids(pkt);

    clientOrigDcid = cids.$1;
    peerScid = cids.$2;

    final initialSalt = Uint8List.fromList(
      HEX.decode("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    );

    final initialSecret = hkdfExtract(clientOrigDcid, salt: initialSalt);

    final clientSecret = hkdfExpandLabel(
      secret: initialSecret,
      label: "client in",
      context: Uint8List(0),
      length: 32,
    );

    final serverSecret = hkdfExpandLabel(
      secret: initialSecret,
      label: "server in",
      context: Uint8List(0),
      length: 32,
    );

    final clientKey = hkdfExpandLabel(
      secret: clientSecret,
      label: "quic key",
      context: Uint8List(0),
      length: 16,
    );
    final clientIv = hkdfExpandLabel(
      secret: clientSecret,
      label: "quic iv",
      context: Uint8List(0),
      length: 12,
    );
    final clientHp = hkdfExpandLabel(
      secret: clientSecret,
      label: "quic hp",
      context: Uint8List(0),
      length: 16,
    );

    final serverKey = hkdfExpandLabel(
      secret: serverSecret,
      label: "quic key",
      context: Uint8List(0),
      length: 16,
    );
    final serverIv = hkdfExpandLabel(
      secret: serverSecret,
      label: "quic iv",
      context: Uint8List(0),
      length: 12,
    );
    final serverHp = hkdfExpandLabel(
      secret: serverSecret,
      label: "quic hp",
      context: Uint8List(0),
      length: 16,
    );

    initialRead = QuicKeys(key: clientKey, iv: clientIv, hp: clientHp);
    initialWrite = QuicKeys(key: serverKey, iv: serverIv, hp: serverHp);

    initialKeysReady = true;

    print("✅ Server Initial keys ready");
    print("  initialRead : $initialRead");
    print("  initialWrite: $initialWrite");
    print("  clientOrigDcid: ${HEX.encode(clientOrigDcid)}");
    print("  peerScid      : ${HEX.encode(peerScid)}");
    print("  localCid      : ${HEX.encode(localCid)}");
  }

  (Uint8List, Uint8List) _extractLongHeaderCids(Uint8List pkt) {
    int off = 1;
    off += 4;

    final dcidLen = pkt[off++];
    final dcid = pkt.sublist(off, off + dcidLen);
    off += dcidLen;

    final scidLen = pkt[off++];
    final scid = pkt.sublist(off, off + scidLen);

    return (dcid, scid);
  }

  // ============================================================
  // Packet decryption
  // ============================================================

  QuicDecryptedPacket decryptPacket(Uint8List packet, EncryptionLevel level) {
    final keys = switch (level) {
      EncryptionLevel.initial => initialRead,
      EncryptionLevel.handshake => handshakeRead,
      EncryptionLevel.application => appRead,
    };

    if (keys == null) {
      throw StateError("No read keys for $level");
    }

    final dcidForLevel = switch (level) {
      EncryptionLevel.initial => clientOrigDcid,
      EncryptionLevel.handshake => localCid,
      EncryptionLevel.application => localCid,
    };

    final pnSpace = recvPnSpaces[level]!;

    final result = decryptQuicPacketBytes(
      packet,
      keys.key,
      keys.iv,
      keys.hp,
      dcidForLevel,
      pnSpace.largestPn,
    );

    if (result == null) {
      throw StateError("Decryption failed for $level");
    }

    pnSpace.onPacketDecrypted(result.packetNumber);
    return result;
  }

  // ============================================================
  // ACK handling
  // ============================================================

  void _onDecryptedPacket(
    QuicDecryptedPacket pkt,
    EncryptionLevel level,
    bool ackEliciting,
  ) {
    ackStates[level]!.received.add(pkt.packetNumber);

    if (!ackEliciting) {
      return;
    }

    if (handshakeComplete) {
      sendAck(level: EncryptionLevel.application);
      return;
    }

    if (level == EncryptionLevel.initial ||
        level == EncryptionLevel.handshake) {
      sendAck(level: level);
    }
  }

  int _allocateSendPn(EncryptionLevel level) {
    final pn = nextSendPn[level]!;
    nextSendPn[level] = pn + 1;
    return pn;
  }

  void sendAck({required EncryptionLevel level}) {
    final ackState = ackStates[level];
    if (ackState == null || ackState.received.isEmpty) {
      return;
    }

    final ackFrame = buildAckFromSet(
      ackState.received,
      ackDelayMicros: 0,
      ect0: 0,
      ect1: 0,
      ce: 0,
    );

    Uint8List ackPayload = ackFrame.encode();
    final pn = _allocateSendPn(level);

    final writeKeys = switch (level) {
      EncryptionLevel.initial => initialWrite,
      EncryptionLevel.handshake => handshakeWrite,
      EncryptionLevel.application => appWrite,
    };

    if (writeKeys == null) {
      throw StateError("Write keys not available for $level");
    }

    final Uint8List dcidToUse = peerScid;
    final Uint8List scidToUse = localCid;

    Uint8List? rawPacket;

    if (level == EncryptionLevel.initial) {
      while (true) {
        rawPacket = encryptQuicPacket(
          "initial",
          ackPayload,
          writeKeys.key,
          writeKeys.iv,
          writeKeys.hp,
          pn,
          dcidToUse,
          scidToUse,
          Uint8List(0),
        );

        if (rawPacket == null) {
          print("❌ Failed to encrypt ACK ($level)");
          return;
        }

        if (rawPacket.length >= 1200) break;

        final deficit = 1200 - rawPacket.length;
        ackPayload = Uint8List.fromList([...ackPayload, ...Uint8List(deficit)]);
      }
    } else if (level == EncryptionLevel.handshake) {
      rawPacket = encryptQuicPacket(
        "handshake",
        ackPayload,
        writeKeys.key,
        writeKeys.iv,
        writeKeys.hp,
        pn,
        dcidToUse,
        scidToUse,
        Uint8List(0),
      );
    } else {
      rawPacket = encryptQuicPacket(
        "short",
        ackPayload,
        writeKeys.key,
        writeKeys.iv,
        writeKeys.hp,
        pn,
        dcidToUse,
        scidToUse,
        Uint8List(0),
      );
    }

    if (handshakeComplete && level != EncryptionLevel.application) {
      throw StateError("BUG: non-application ACK after handshake");
    }

    if (rawPacket == null) {
      print("❌ Failed to encrypt ACK ($level)");
      return;
    }

    socket.send(rawPacket, peerAddress, peerPort);

    print(
      "✅ Sent ACK ($level) pn=$pn acked=${ackState.received.toList()..sort()}",
    );
  }

  // ============================================================
  // Payload / frame parsing
  // ============================================================

  bool _parsePayload(Uint8List plaintext, EncryptionLevel level) {
    print('--- Parsing Decrypted QUIC Payload (server) ---');

    final buffer = QuicBuffer(data: plaintext);
    bool ackEliciting = false;

    try {
      while (buffer.remaining > 0) {
        final frameType = buffer.pullVarInt();

        if (frameType == 0x00) {
          continue;
        }

        if (frameType == 0x01) {
          print('✅ Server parsed PING');
          ackEliciting = true;
          continue;
        }

        if (frameType == 0x02 || frameType == 0x03) {
          final hasEcn = (frameType & 0x01) == 0x01;

          if (buffer.remaining == 0) break;
          final largest = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final delay = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final rangeCount = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final firstRange = buffer.pullVarInt();

          for (int i = 0; i < rangeCount; i++) {
            if (buffer.remaining == 0) break;
            buffer.pullVarInt();

            if (buffer.remaining == 0) break;
            buffer.pullVarInt();
          }

          if (hasEcn) {
            if (buffer.remaining == 0) break;
            buffer.pullVarInt();

            if (buffer.remaining == 0) break;
            buffer.pullVarInt();

            if (buffer.remaining == 0) break;
            buffer.pullVarInt();
          }

          print(
            '✅ Server parsed ACK largest=$largest delay=$delay firstRange=$firstRange',
          );
          continue;
        }

        if (frameType == 0x06) {
          if (buffer.remaining == 0) break;
          final offset = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final length = buffer.pullVarInt();

          if (buffer.remaining < length) {
            print(
              '🛑 Server CRYPTO frame truncated: need $length, have ${buffer.remaining}',
            );
            break;
          }

          final data = buffer.pullBytes(length);

          print('✅ Server parsed CRYPTO frame offset=$offset len=$length');
          ackEliciting = true;

          cryptoChunksByLevel[level]![offset] = data;
          final assembled = assembleCryptoStream(level);

          if (assembled.isNotEmpty) {
            receivedHandshakeByLevel[level]!.add(assembled);

            if (level == EncryptionLevel.initial) {
              _maybeHandleClientHello();
            } else if (level == EncryptionLevel.handshake) {
              _maybeHandleClientFinished();
            }
          }
          continue;
        }

        // STREAM frames (0x08..0x0f)
        if ((frameType & 0xF8) == 0x08) {
          final fin = (frameType & 0x01) != 0;
          final hasLen = (frameType & 0x02) != 0;
          final hasOff = (frameType & 0x04) != 0;

          if (buffer.remaining == 0) break;
          final streamId = buffer.pullVarInt();

          final streamOffset = hasOff ? buffer.pullVarInt() : 0;
          final dataLen = hasLen ? buffer.pullVarInt() : buffer.remaining;

          if (buffer.remaining < dataLen) {
            print(
              '🛑 Server STREAM frame truncated: need $dataLen, have ${buffer.remaining}',
            );
            break;
          }

          final data = buffer.pullBytes(dataLen);

          print(
            '✅ Server parsed STREAM streamId=$streamId '
            'offset=$streamOffset len=$dataLen fin=$fin',
          );

          ackEliciting = true;

          if (level == EncryptionLevel.application) {
            handleHttp3StreamChunk(streamId, streamOffset, data, fin: fin);
          } else {
            print('ℹ️ Ignoring non-application STREAM frame on level=$level');
          }

          continue;
        }

        // DATAGRAM frames (0x30, 0x31)
        if (frameType == 0x30 || frameType == 0x31) {
          final hasLen = frameType == 0x31;
          final datagramLen = hasLen ? buffer.pullVarInt() : buffer.remaining;

          if (buffer.remaining < datagramLen) {
            print(
              '🛑 Server DATAGRAM frame truncated: need $datagramLen, have ${buffer.remaining}',
            );
            break;
          }

          final payload = buffer.pullBytes(datagramLen);

          print('✅ Server parsed DATAGRAM len=${payload.length}');
          ackEliciting = true;

          if (level == EncryptionLevel.application) {
            handleWebTransportDatagram(payload);
          } else {
            print('ℹ️ Ignoring non-application DATAGRAM frame on level=$level');
          }

          continue;
        }

        if (frameType == 0x1e) {
          print('✅ Server parsed HANDSHAKE_DONE');
          ackEliciting = true;
          continue;
        }

        if (frameType == 0x1c || frameType == 0x1d) {
          if (buffer.remaining == 0) break;
          final errorCode = buffer.pullVarInt();

          int? offendingFrameType;
          if (frameType == 0x1c) {
            if (buffer.remaining == 0) break;
            offendingFrameType = buffer.pullVarInt();
          }

          if (buffer.remaining == 0) break;
          final reasonLen = buffer.pullVarInt();

          if (buffer.remaining < reasonLen) {
            print(
              '🛑 Server CONNECTION_CLOSE reason truncated: need $reasonLen, have ${buffer.remaining}',
            );
            break;
          }

          final reasonBytes = reasonLen > 0
              ? buffer.pullBytes(reasonLen)
              : Uint8List(0);

          final reason = utf8.decode(reasonBytes, allowMalformed: true);

          print(
            '🛑 Server parsed CONNECTION_CLOSE '
            'frameType=0x${frameType.toRadixString(16)} '
            'errorCode=0x${errorCode.toRadixString(16)} '
            '${offendingFrameType != null ? 'offendingFrameType=0x${offendingFrameType.toRadixString(16)} ' : ''}'
            'reason="$reason"',
          );
          break;
        }

        print(
          'ℹ️ Server stopping on unsupported frame type 0x${frameType.toRadixString(16)}',
        );
        break;
      }
    } catch (e, st) {
      print('🛑 Server payload parse error: $e\n$st');
    }

    print('🎉 Server payload parsing complete.');
    return ackEliciting;
  }

  Uint8List assembleCryptoStream(EncryptionLevel level) {
    final chunks = cryptoChunksByLevel[level]!;
    int readOffset = cryptoReadOffsetByLevel[level]!;

    final out = <int>[];
    while (chunks.containsKey(readOffset)) {
      final chunk = chunks.remove(readOffset)!;
      out.addAll(chunk);
      readOffset += chunk.length;
    }

    cryptoReadOffsetByLevel[level] = readOffset;
    return Uint8List.fromList(out);
  }

  // bool _streamContainsHandshakeType(BytesBuilder bb, int expectedType) {
  //   final data = bb.toBytes();
  //   int i = 0;

  //   while (i + 4 <= data.length) {
  //     final type = data[i];
  //     final len = (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3];

  //     if (i + 4 + len > data.length) break;
  //     if (type == expectedType) return true;
  //     i += 4 + len;
  //   }

  //   return false;
  // }

  Uint8List? _extractHandshakeMessage(BytesBuilder bb, int expectedType) {
    final data = bb.toBytes();
    int i = 0;

    while (i + 4 <= data.length) {
      final type = data[i];
      final len = (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3];

      if (i + 4 + len > data.length) break;

      if (type == expectedType) {
        return data.sublist(i, i + 4 + len);
      }

      i += 4 + len;
    }

    return null;
  }

  // ============================================================
  // ClientHello handling → derive handshake keys → send flight
  // ============================================================
  void _maybeUpdatePeerCidFromPacket(Uint8List pkt) {
    final isLong = (pkt[0] & 0x80) != 0;
    if (!isLong) return;

    final cids = _extractLongHeaderCids(pkt);
    final newPeerScid = cids.$2;

    if (newPeerScid.isEmpty) return;

    final changed = !const ListEquality<int>().equals(newPeerScid, peerScid);
    if (changed) {
      peerScid = Uint8List.fromList(newPeerScid);
      print('🔄 Updated peerScid to ${HEX.encode(peerScid)}');
    }
  }

  void handleDatagram(Uint8List pkt) {
    final packetLevel = detectPacketLevel(pkt);
    print("📥 Server received packet level=$packetLevel len=${pkt.length}");

    // Learn newer client CID from later long-header packets.
    // This is critical before sending any 1-RTT short-header packets.
    if (initialKeysReady) {
      _maybeUpdatePeerCidFromPacket(pkt);
    }

    if (!initialKeysReady) {
      if (packetLevel != EncryptionLevel.initial) {
        print("ℹ️ Ignoring non-Initial packet before initial keys are ready");
        return;
      }
      _deriveInitialKeysFromFirstPacket(pkt);

      // Also update after the very first Initial
      _maybeUpdatePeerCidFromPacket(pkt);
    }

    if (packetLevel == EncryptionLevel.handshake && handshakeRead == null) {
      print("ℹ️ Ignoring early Handshake packet (handshake keys not ready)");
      return;
    }

    if (packetLevel == EncryptionLevel.application &&
        !applicationSecretsDerived) {
      print("ℹ️ Ignoring early Application packet (1-RTT keys not ready)");
      return;
    }

    final decrypted = decryptPacket(pkt, packetLevel);
    final ackEliciting = _parsePayload(decrypted.plaintext!, packetLevel);
    _onDecryptedPacket(decrypted, packetLevel, ackEliciting);
  }

  void _maybeHandleClientHello() {
    if (serverFlightSent) return;

    final BytesBuilder stream =
        receivedHandshakeByLevel[EncryptionLevel.initial]!;

    final Uint8List? msg = _extractHandshakeMessage(stream, 0x01);
    if (msg == null) {
      return;
    }

    clientHelloMsg = msg;

    final ClientHello clientHello = ClientHello.parse_tls_client_hello(
      msg.sublist(4),
    );

    print("✅ Server has full ClientHello");

    final List<String> clientOfferedAlpns = clientHello.alpnProtocols.isEmpty
        ? <String>[]
        : clientHello.alpnProtocols;

    final String selectedAlpn = clientOfferedAlpns.isEmpty
        ? alpnQuicEchoExample
        : chooseServerAlpn(clientOfferedAlpns);

    print("✅ Client offered ALPNs: $clientOfferedAlpns");
    print("✅ Server selected ALPN: $selectedAlpn");

    _deriveHandshakeKeys(clientHello);

    if (serverHelloMsg == null) {
      throw StateError("serverHelloMsg not initialized");
    }

    final ServerHandshakeArtifacts artifacts = buildServerHandshakeArtifacts(
      serverRandom: serverRandom,
      serverPublicKey: keyPair.publicKeyBytes,
      serverCert: serverCert,
      transcriptPrefixBeforeCertVerify: Uint8List.fromList([
        ...clientHelloMsg!,
        ...serverHelloMsg!,
      ]),
      alpnProtocol: selectedAlpn,
      originalDestinationConnectionId: clientOrigDcid,
      initialSourceConnectionId: localCid,
    );

    _storeServerHandshakeArtifacts(artifacts);
    _sendServerHandshakeFlight();
    serverFlightSent = true;
  }

  void _deriveHandshakeKeys(ClientHello clientHello) {
    final keyShare = clientHello.keyShares!.firstWhere(
      (ks) => ks.group == 0x001d,
      orElse: () => throw StateError("No X25519 key_share"),
    );

    final sharedSecret = x25519ShareSecret(
      privateKey: keyPair.privateKeyBytes,
      publicKey: keyShare.pub,
    );

    serverHelloMsg = buildServerHello(
      serverRandom: serverRandom,
      publicKey: keyPair.publicKeyBytes,
      sessionId: Uint8List(0),
      cipherSuite: 0x1301,
      group: keyShare.group,
    );

    final helloTranscript = Uint8List.fromList([
      ...clientHelloMsg!,
      ...serverHelloMsg!,
    ]);

    final helloHash = createHash(helloTranscript);

    final hashLen = 32;
    final zero = Uint8List(hashLen);
    final empty = Uint8List(0);
    final emptyHash = createHash(empty);

    final earlySecret = hkdfExtract(zero, salt: empty);

    derivedSecret = hkdfExpandLabel(
      secret: earlySecret,
      label: "derived",
      context: emptyHash,
      length: hashLen,
    );

    handshakeSecret = hkdfExtract(sharedSecret, salt: derivedSecret);

    clientHsTrafficSecret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "c hs traffic",
      context: helloHash,
      length: hashLen,
    );

    serverHsTrafficSecret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "s hs traffic",
      context: helloHash,
      length: hashLen,
    );

    final clientKey = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );
    final clientIv = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );
    final clientHp = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    final serverKey = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );
    final serverIv = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );
    final serverHp = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    handshakeRead = QuicKeys(key: clientKey, iv: clientIv, hp: clientHp);
    handshakeWrite = QuicKeys(key: serverKey, iv: serverIv, hp: serverHp);

    handshakeKeysReady = true;

    print("✅ Server handshake keys ready");
    print("  handshakeRead : $handshakeRead");
    print("  handshakeWrite: $handshakeWrite");
  }

  void _storeServerHandshakeArtifacts(ServerHandshakeArtifacts artifacts) {
    encryptedExtensions = artifacts.encryptedExtensions;
    certificate = artifacts.certificate;
    certificateVerify = artifacts.certificateVerify;

    print("✅ Server handshake artifacts stored");
    print("  encryptedExtensions: ${encryptedExtensions.length} bytes");
    print("  certificate        : ${certificate.length} bytes");
    print("  certificateVerify  : ${certificateVerify.length} bytes");
  }

  void _sendServerHandshakeFlight() {
    if (initialWrite == null) {
      throw StateError("Initial write keys not ready");
    }
    if (handshakeWrite == null) {
      throw StateError("Handshake write keys not ready");
    }
    if (clientHelloMsg == null || serverHelloMsg == null) {
      throw StateError("Handshake transcript not initialized");
    }

    final handshakeBeforeFinished = Uint8List.fromList([
      ...clientHelloMsg!,
      ...serverHelloMsg!,
      ...encryptedExtensions,
      ...certificate,
      ...certificateVerify,
    ]);

    final transcriptHash = createHash(handshakeBeforeFinished);

    final serverFinishedKey = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "finished",
      context: Uint8List(0),
      length: 32,
    );

    final verifyData = hmacSha256(key: serverFinishedKey, data: transcriptHash);

    serverFinishedBytes = Uint8List.fromList([
      0x14,
      0x00,
      0x00,
      verifyData.length,
      ...verifyData,
    ]);

    transcriptThroughServerFinishedBytes = Uint8List.fromList([
      ...clientHelloMsg!,
      ...serverHelloMsg!,
      ...encryptedExtensions,
      ...certificate,
      ...certificateVerify,
      ...serverFinishedBytes!,
    ]);

    serverHandshakeFinished = true;

    print("✅ Server built Finished verify_data=${HEX.encode(verifyData)}");

    {
      final crypto = buildCryptoFrameAt(0, serverHelloMsg!);
      final pn = _allocateSendPn(EncryptionLevel.initial);

      final raw = encryptQuicPacket(
        "initial",
        crypto,
        initialWrite!.key,
        initialWrite!.iv,
        initialWrite!.hp,
        pn,
        peerScid,
        localCid,
        Uint8List(0),
      );

      if (raw == null) {
        throw StateError("Failed to encrypt Initial ServerHello");
      }

      socket.send(raw, peerAddress, peerPort);
      print(
        "✅ Server sent Initial(ServerHello) pn=$pn "
        "dcid=${HEX.encode(peerScid)} scid=${HEX.encode(localCid)}",
      );
    }

    int offset = 0;

    void sendHandshake(Uint8List msg) {
      final crypto = buildCryptoFrameAt(offset, msg);
      final pn = _allocateSendPn(EncryptionLevel.handshake);

      final raw = encryptQuicPacket(
        "handshake",
        crypto,
        handshakeWrite!.key,
        handshakeWrite!.iv,
        handshakeWrite!.hp,
        pn,
        peerScid,
        localCid,
        Uint8List(0),
      );

      if (raw == null) {
        throw StateError("Failed to encrypt Handshake packet");
      }

      socket.send(raw, peerAddress, peerPort);
      print(
        "✅ Server sent Handshake pn=$pn offset=$offset len=${msg.length} "
        "dcid=${HEX.encode(peerScid)} scid=${HEX.encode(localCid)}",
      );

      offset += msg.length;
    }

    sendHandshake(encryptedExtensions);
    sendHandshake(certificate);
    sendHandshake(certificateVerify);
    sendHandshake(serverFinishedBytes!);
  }

  Uint8List buildCryptoFrameAt(int offset, Uint8List data) {
    return Uint8List.fromList([
      0x06,
      ...encodeVarInt(offset),
      ...encodeVarInt(data.length),
      ...data,
    ]);
  }

  List<int> encodeVarInt(int value) {
    if (value < 0x40) {
      return [value];
    } else if (value < 0x4000) {
      return [0x40 | ((value >> 8) & 0x3f), value & 0xff];
    } else if (value < 0x40000000) {
      return [
        0x80 | ((value >> 24) & 0x3f),
        (value >> 16) & 0xff,
        (value >> 8) & 0xff,
        value & 0xff,
      ];
    } else {
      throw ArgumentError("varint too large for this helper: $value");
    }
  }
  // ============================================================
  // Client Finished handling
  // ============================================================

  void _maybeHandleClientFinished() {
    if (clientFinishedVerified) return;

    final stream = receivedHandshakeByLevel[EncryptionLevel.handshake]!;
    final fullFinished = _extractHandshakeMessage(stream, 0x14);
    if (fullFinished == null) {
      return;
    }

    if (transcriptThroughServerFinishedBytes == null) {
      throw StateError("Server transcript through Finished not prepared");
    }

    final transcriptHash = createHash(transcriptThroughServerFinishedBytes!);

    final clientFinishedKey = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "finished",
      context: Uint8List(0),
      length: 32,
    );

    final expectedVerifyData = hmacSha256(
      key: clientFinishedKey,
      data: transcriptHash,
    );

    final receivedVerifyData = fullFinished.sublist(4);

    final ok = const ListEquality<int>().equals(
      expectedVerifyData,
      receivedVerifyData,
    );

    print("✅ Server received Client Finished");
    print("  expected: ${HEX.encode(expectedVerifyData)}");
    print("  actual  : ${HEX.encode(receivedVerifyData)}");

    if (!ok) {
      throw StateError("Client Finished verify_data mismatch");
    }

    clientFinishedVerified = true;
    handshakeComplete = true;

    print("✅ Client Finished verified");

    _deriveApplicationSecrets();

    // ✅ Start HTTP/3 / WebTransport immediately after 1-RTT is ready
    sendHttp3ControlStream();
  }

  // ============================================================
  // Application (1-RTT) secrets
  // ============================================================

  void _deriveApplicationSecrets() {
    if (applicationSecretsDerived) return;

    final hashLen = 32;
    final zero = Uint8List(hashLen);
    final empty = Uint8List(0);

    if (transcriptThroughServerFinishedBytes == null) {
      throw StateError("Server transcript through Finished not prepared");
    }

    final transcriptHash = createHash(transcriptThroughServerFinishedBytes!);
    final empty_hash = createHash(Uint8List(0));
    final derived_secret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "derived",
      context: empty_hash,
      length: hashLen,
    );
    final masterSecret = hkdfExtract(zero, salt: derived_secret);

    final clientAppTrafficSecret = hkdfExpandLabel(
      secret: masterSecret,
      label: "c ap traffic",
      context: transcriptHash,
      length: hashLen,
    );

    final serverAppTrafficSecret = hkdfExpandLabel(
      secret: masterSecret,
      label: "s ap traffic",
      context: transcriptHash,
      length: hashLen,
    );

    final clientKey = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );
    final clientIv = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );
    final clientHp = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    final serverKey = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );
    final serverIv = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );
    final serverHp = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    appRead = QuicKeys(key: clientKey, iv: clientIv, hp: clientHp);
    appWrite = QuicKeys(key: serverKey, iv: serverIv, hp: serverHp);

    applicationSecretsDerived = true;
    encryptionLevel = EncryptionLevel.application;

    print("✅ Server 1-RTT keys installed");
    print("  appRead : $appRead");
    print("  appWrite: $appWrite");
  }

  // ============================================================
  // HTTP/3 + WebTransport methods
  // ============================================================

  void sendHttp3ControlStream() {
    if (h3.controlStreamSent) return;
    if (!applicationSecretsDerived || appWrite == null) {
      throw StateError('Cannot send HTTP/3 control stream before 1-RTT keys');
    }

    final settingsPayload = build_settings_frame({
      'SETTINGS_QPACK_MAX_TABLE_CAPACITY': 0,
      'SETTINGS_QPACK_BLOCKED_STREAMS': 0,
      'SETTINGS_ENABLE_CONNECT_PROTOCOL': 1,
      'SETTINGS_ENABLE_WEBTRANSPORT': 1,
      'SETTINGS_H3_DATAGRAM': 1,
    });

    final controlStreamBytes = Uint8List.fromList([
      ...writeVarInt(H3_STREAM_TYPE_CONTROL),
      ...writeVarInt(H3_FRAME_SETTINGS),
      ...writeVarInt(settingsPayload.length),
      ...settingsPayload,
    ]);

    sendApplicationUnidirectionalStream(controlStreamBytes, fin: false);
    h3.controlStreamSent = true;

    print('✅ HTTP/3 control stream sent');
  }

  void handleHttp3StreamChunk(
    int streamId,
    int streamOffset,
    Uint8List streamData, {
    required bool fin,
  }) {
    final chunks = h3.streamChunks.putIfAbsent(
      streamId,
      () => <int, Uint8List>{},
    );
    final readOffset = h3.streamReadOffsets[streamId] ?? 0;

    chunks[streamOffset] = streamData;

    final extracted = extract_h3_frames_from_chunks(chunks, readOffset);
    h3.streamReadOffsets[streamId] = extracted['new_from_offset'] as int;

    for (final frame in extracted['frames']) {
      final int type = frame['frame_type'] as int;
      final Uint8List payload = frame['payload'] as Uint8List;

      if (type == H3_FRAME_HEADERS) {
        _handleHttp3HeadersFrame(streamId, payload);
        continue;
      }

      if (type == H3_FRAME_DATA) {
        print('📦 HTTP/3 DATA on stream=$streamId len=${payload.length}');
        continue;
      }

      if (type == H3_FRAME_SETTINGS) {
        print('ℹ️ Ignoring unexpected SETTINGS on stream=$streamId');
        continue;
      }

      print(
        'ℹ️ Ignoring unsupported HTTP/3 frame type '
        '0x${type.toRadixString(16)} on stream=$streamId',
      );
    }

    if (fin) {
      print('✅ QUIC stream $streamId FIN received');
    }
  }

  void _handleHttp3HeadersFrame(int streamId, Uint8List headerBlock) {
    final headers = decode_qpack_header_fields(headerBlock);

    String method = '';
    String path = '';
    String protocol = '';

    for (final h in headers) {
      if (h.name == ':method') method = h.value;
      if (h.name == ':path') path = h.value;
      if (h.name == ':protocol') protocol = h.value;
    }

    if (method == 'CONNECT' && protocol == WT_PROTOCOL) {
      _acceptWebTransportSession(streamId);
      return;
    }

    print('📥 HTTP/3 request on stream $streamId: $method $path');

    final body = Uint8List.fromList(utf8.encode('hello from http/3'));

    final responseHeaderBlock = build_http3_literal_headers_frame({
      ':status': '200',
      'content-type': 'text/plain; charset=utf-8',
      'content-length': body.length,
    });

    final responseFrames = build_h3_frames([
      {'frame_type': H3_FRAME_HEADERS, 'payload': responseHeaderBlock},
      {'frame_type': H3_FRAME_DATA, 'payload': body},
    ]);

    sendApplicationStream(streamId, responseFrames, fin: true);
  }

  void _acceptWebTransportSession(int streamId) {
    print('✅ WebTransport session accepted on stream $streamId');

    h3.webTransportSessions[streamId] = WebTransportSession(streamId);

    final responseHeaderBlock = build_http3_literal_headers_frame({
      ':status': '200',
      'sec-webtransport-http3-draft': 'draft02',
    });

    final frames = build_h3_frames([
      {'frame_type': H3_FRAME_HEADERS, 'payload': responseHeaderBlock},
    ]);

    sendApplicationStream(streamId, frames, fin: false);
  }

  void handleWebTransportDatagram(Uint8List datagramPayload) {
    final parsed = parse_webtransport_datagram(datagramPayload);
    final int sessionId = parsed['stream_id'] as int;
    final Uint8List data = parsed['data'] as Uint8List;

    final session = h3.webTransportSessions[sessionId];
    if (session == null) {
      print('⚠️ Datagram for unknown WebTransport session $sessionId');
      return;
    }

    print('📦 WebTransport datagram session=$sessionId len=${data.length}');
    sendWebTransportDatagram(sessionId, data);
  }

  void sendApplicationStream(
    int streamId,
    Uint8List data, {
    bool fin = false,
    int offset = 0,
  }) {
    if (!applicationSecretsDerived || appWrite == null) {
      throw StateError('Cannot send application stream before 1-RTT keys');
    }

    final frame = _buildStreamFrame(
      streamId: streamId,
      data: data,
      offset: offset,
      fin: fin,
    );

    final pn = _allocateSendPn(EncryptionLevel.application);

    final raw = encryptQuicPacket(
      'short',
      frame,
      appWrite!.key,
      appWrite!.iv,
      appWrite!.hp,
      pn,
      peerScid,
      localCid,
      Uint8List(0),
    );

    if (raw == null) {
      throw StateError('Failed to encrypt application STREAM packet');
    }

    socket.send(raw, peerAddress, peerPort);

    print(
      '✅ Sent application STREAM pn=$pn streamId=$streamId '
      'len=${data.length} fin=$fin',
    );
  }

  int _allocateServerUniStreamId() {
    final id = nextServerUniStreamId;
    nextServerUniStreamId += 4;
    return id;
  }

  void sendApplicationUnidirectionalStream(Uint8List data, {bool fin = false}) {
    final streamId = _allocateServerUniStreamId();
    sendApplicationStream(streamId, data, fin: fin, offset: 0);
  }

  void sendWebTransportDatagram(int sessionId, Uint8List data) {
    if (!applicationSecretsDerived || appWrite == null) {
      throw StateError('Cannot send WebTransport DATAGRAM before 1-RTT keys');
    }

    final payload = Uint8List.fromList([...writeVarInt(sessionId), ...data]);

    final frame = _buildDatagramFrame(payload, useLengthField: true);
    final pn = _allocateSendPn(EncryptionLevel.application);

    final raw = encryptQuicPacket(
      'short',
      frame,
      appWrite!.key,
      appWrite!.iv,
      appWrite!.hp,
      pn,
      peerScid,
      localCid,
      Uint8List(0),
    );

    if (raw == null) {
      throw StateError('Failed to encrypt DATAGRAM packet');
    }

    socket.send(raw, peerAddress, peerPort);

    print(
      '✅ Sent WebTransport DATAGRAM pn=$pn session=$sessionId len=${data.length}',
    );
  }

  Uint8List _buildStreamFrame({
    required int streamId,
    required Uint8List data,
    int offset = 0,
    bool fin = false,
  }) {
    int frameType = 0x08;
    if (fin) frameType |= 0x01;
    frameType |= 0x02;
    if (offset != 0) frameType |= 0x04;

    return Uint8List.fromList([
      ...writeVarInt(frameType),
      ...writeVarInt(streamId),
      if (offset != 0) ...writeVarInt(offset),
      ...writeVarInt(data.length),
      ...data,
    ]);
  }

  Uint8List _buildDatagramFrame(
    Uint8List payload, {
    bool useLengthField = true,
  }) {
    if (useLengthField) {
      return Uint8List.fromList([
        ...writeVarInt(0x31),
        ...writeVarInt(payload.length),
        ...payload,
      ]);
    }

    return Uint8List.fromList([...writeVarInt(0x30), ...payload]);
  }
}
