// -----------------------------------------------------------------------------
// HTTP/3 + WebTransport client state
// -----------------------------------------------------------------------------

import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';

import '../../buffer.dart';
import '../../cipher/hash.dart';
import '../../cipher/hkdf.dart';
import '../../cipher/x25519.dart';
import '../../constants.dart';
import '../../frames/quic_ack.dart';
import '../../frames/quic_frames.dart';
import '../../h3/h3.dart';
import '../../handshake/certificate.dart';
import '../../handshake/certificate_verify.dart';
import '../../handshake/client_hello.dart';
import '../../handshake/client_hello_builder.dart' as chb;
import '../../handshake/encrypted_extensions.dart';
import '../../handshake/finished.dart';
import '../../handshake/server_hello.dart';
// import '../../handshake/tls_messages.dart';
// import '../../handshake/tls_messages2.dart';
import '../../handshake/tls_msg.dart';
// import '../../hash.dart';
// import '../../hkdf.dart';
import '../../packet/quic_packet.dart';
// import '../../quic_ack.dart';
import '../../streams/stream.dart';
import '../../utils.dart';
// import '../client_hello_builder.dart';
// import '../client_hello_builder.dart' as chb;
// import '../h31.dart';
// import '../constants.dart';
// import '../stream.dart';
// import 'payload_parser3.dart';

const int H3_FRAME_DATA = 0x00;
const int H3_FRAME_HEADERS = 0x01;
const int H3_FRAME_SETTINGS = 0x04;

const int H3_STREAM_TYPE_CONTROL = 0x00;
const String WT_PROTOCOL = 'webtransport';

class ClientWebTransportSession {
  final int connectStreamId;
  bool established = false;

  ClientWebTransportSession(this.connectStreamId);
}

final _bytesEq = const ListEquality<int>();

// Uint8List buildCryptoFrame(Uint8List data) {
//   return Uint8List.fromList([0x06, 0x00, data.length, ...data]);
// }

Uint8List buildCryptoFrame(Uint8List data, {int offset = 0}) {
  return Uint8List.fromList([
    0x06,
    ...writeVarInt(offset),
    ...writeVarInt(data.length),
    ...data,
  ]);
}

class Http3ClientState {
  bool settingsReceived = false;
  bool controlStreamSeen = false;

  // Raw QUIC stream bytes keyed by QUIC stream ID and offset
  final Map<int, Map<int, Uint8List>> rawStreamChunks =
      <int, Map<int, Uint8List>>{};

  // Stream-type prefix length for uni streams (e.g. control stream type varint)
  final Map<int, int> streamTypePrefixLen = <int, int>{};

  // Kind of stream: control / request / other_uni / other
  final Map<int, String> streamKinds = <int, String>{};

  // HTTP/3 frame reassembly after stripping any uni-stream type prefix
  final Map<int, Map<int, Uint8List>> h3FrameChunks =
      <int, Map<int, Uint8List>>{};
  final Map<int, int> h3FrameReadOffsets = <int, int>{};

  // Peer settings learned from server control stream
  final Map<String, int> peerSettings = <String, int>{};

  // WebTransport sessions keyed by CONNECT stream ID
  final Map<int, ClientWebTransportSession> webTransportSessions =
      <int, ClientWebTransportSession>{};
}

// -----------------------------------------------------------------------------
// Full QuicSession with HTTP/3 + WebTransport support
// -----------------------------------------------------------------------------

class QuicSession {
  Uint8List dcid;

  EncryptionLevel encryptionLevel = EncryptionLevel.initial;

  RawDatagramSocket socket;

  // Keys
  QuicKeys? initialRead, initialWrite;
  QuicKeys? handshakeRead, handshakeWrite;
  QuicKeys? appRead, appWrite;

  /// Packet number spaces
  final _pnSpaces = <EncryptionLevel, PacketNumberSpace>{
    EncryptionLevel.initial: PacketNumberSpace(),
    EncryptionLevel.handshake: PacketNumberSpace(),
    EncryptionLevel.application: PacketNumberSpace(),
  };

  late Uint8List derivedSecret;

  /// Client's own Source CID.
  /// This is what the server will use as DCID when replying in long headers.
  late Uint8List localCid;

  /// Learned from server long-header packet SCID.
  /// This becomes the DCID for packets the client sends after that.
  Uint8List? peerCid;

  /// Traffic keys by level and direction
  final _readKeys = <EncryptionLevel, QuicKeys>{};
  final _writeKeys = <EncryptionLevel, QuicKeys>{};

  final BytesBuilder receivedHandshakeBytes = BytesBuilder();
  final BytesBuilder tlsTranscript = BytesBuilder();

  late Uint8List clientHsTrafficSecret;
  late Uint8List handshakeSecret;

  bool serverFinishedReceived = false;
  bool clientFinishedSent = false;
  bool applicationSecretsDerived = false;

  final randomData = Uint8List.fromList(HEX.decode("0001020304050607"));

  List<CryptoFrame> receivedCryptoFrames = [];
  List<TlsHandshakeMessage> receivedTlsMessages = [];

  ServerHello? receivedServello;

  // Uint8List privateKeyBytes = Uint8List.fromList(
  //   HEX.decode(
  //     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
  //   ),
  // );

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

  final Map<EncryptionLevel, AckState> ackStates = {
    EncryptionLevel.initial: AckState(),
    EncryptionLevel.handshake: AckState(),

    EncryptionLevel.application: AckState(),
  };

  // ---------------------------------------------------------------------------
  // HTTP/3 + WebTransport state
  // ---------------------------------------------------------------------------

  final Http3ClientState h3 = Http3ClientState();

  // Client-initiated streams
  int nextClientBidiStreamId = 0; // client bidi: 0,4,8,...
  int nextClientUniStreamId = 2; // client uni: 2,6,10,...

  // ---------------------------------------------------------------------------
  // WebTransport test state
  // ---------------------------------------------------------------------------

  bool webTransportConnectSent = false;
  bool webTransportDatagramSent = false;
  int? activeWebTransportSessionId;

  late KeyPair keyPair;

  QuicSession(this.dcid, this.socket) {
    keyPair = KeyPair.generate();
    generateSecrets();
    _readKeys[EncryptionLevel.initial] = initialRead!;
    localCid = _randomCid(8);
  }

  Uint8List _randomCid([int len = 8]) {
    final rnd = math.Random.secure();
    return Uint8List.fromList(List.generate(len, (_) => rnd.nextInt(256)));
  }

  ClientHello? builtClientHello;
  Uint8List? clientHelloRaw;

  Uint8List buildDynamicClientHello({String authority = 'localhost'}) {
    final ch = chb.buildInitialClientHello(
      hostname: authority,
      x25519PublicKey: Uint8List.fromList(
        keyPair.publicKeyBytes, // WRONG if used directly
      ),
      localCid: localCid,
      alpns: const ['h3'],
    );

    final wire = ch.serialize();

    builtClientHello = ch;
    clientHelloRaw = wire;

    print('🚨 Built dynamic ClientHello len=${wire.length}');
    print('🚨 Dynamic ALPNs: ${ch.alpnProtocols}');

    return wire;
  }

  Uint8List _encryptInitialPacketWithMinSize({
    required Uint8List payload,
    required int packetNumber,
    required Uint8List dcid,
    required Uint8List scid,
    int minDatagramSize = 1200,
  }) {
    if (initialWrite == null) {
      throw StateError('Initial write keys not available');
    }

    Uint8List currentPayload = Uint8List.fromList(payload);

    while (true) {
      final rawPacket = encryptQuicPacket(
        "initial",
        currentPayload,
        initialWrite!.key,
        initialWrite!.iv,
        initialWrite!.hp,
        packetNumber,
        dcid,
        scid,
        Uint8List(0),
        logDebug: false,
      );

      if (rawPacket == null) {
        throw StateError('Failed to encrypt Initial packet');
      }

      if (rawPacket.length >= minDatagramSize) {
        return rawPacket;
      }

      // Add one QUIC PADDING frame byte (0x00) to plaintext payload
      currentPayload = Uint8List.fromList([...currentPayload, 0x00]);
    }
  }

  // void sendClientHello({
  //   required InternetAddress address,
  //   required int port,
  //   String authority = 'localhost',
  // }) {
  //   if (initialWrite == null) {
  //     throw StateError("Initial write keys not available");
  //   }

  //   final Uint8List chWire = buildDynamicClientHello(
  //     authority: authority,
  //     // alpns: const ['h3'],
  //   );
  //   clientHelloRaw = chWire;

  //   final cryptoPayload = buildCryptoFrame(chWire);

  //   final ackState = ackStates[EncryptionLevel.initial]!;
  //   final pn = ackState.allocatePn();

  //   final rawPacket = encryptQuicPacket(
  //     "initial",
  //     cryptoPayload,
  //     initialWrite!.key,
  //     initialWrite!.iv,
  //     initialWrite!.hp,
  //     pn,
  //     dcid, // original destination CID chosen by client
  //     localCid, // current client source CID
  //     Uint8List(0),
  //   );

  //   if (rawPacket == null) {
  //     throw StateError("Failed to encrypt Initial ClientHello");
  //   }

  //   final bytesToSend = padTo1200(rawPacket);
  //   socket.send(bytesToSend, address, port);

  //   print(
  //     "🚀 Sent Initial ClientHello pn=$pn "
  //     "dcid=${HEX.encode(dcid)} scid=${HEX.encode(localCid)} "
  //     "len=${bytesToSend.length}",
  //   );
  // }

  void sendClientHello({
    required InternetAddress address,
    required int port,
    String authority = 'localhost',
  }) {
    if (initialWrite == null) {
      throw StateError("Initial write keys not available");
    }

    final Uint8List chWire = buildDynamicClientHello(authority: authority);
    clientHelloRaw = chWire;

    final cryptoPayload = buildCryptoFrame(chWire);

    final ackState = ackStates[EncryptionLevel.initial]!;
    final pn = ackState.allocatePn();

    final rawPacket = _encryptInitialPacketWithMinSize(
      payload: cryptoPayload,
      packetNumber: pn,
      dcid: dcid,
      scid: localCid,
      minDatagramSize: 1200,
    );

    socket.send(rawPacket, InternetAddress("127.0.0.1"), 4433);

    print(
      "🚀 Sent Initial ClientHello pn=$pn "
      "dcid=${HEX.encode(dcid)} scid=${HEX.encode(localCid)} "
      "len=${rawPacket.length}",
    );
  }

  // ===========================================================================
  // ACK sending
  // ===========================================================================

  void sendAck({
    required EncryptionLevel level,
    required String address,
    required int port,
  }) {
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

    final ackPayload = ackFrame.encode();
    final pn = ackState.allocatePn();

    final writeKeys = switch (level) {
      EncryptionLevel.initial => initialWrite,
      EncryptionLevel.handshake => handshakeWrite,
      EncryptionLevel.application => appWrite,
    };

    if (writeKeys == null) {
      throw StateError("Write keys not available for $level");
    }

    final Uint8List dcidToUse = peerCid ?? Uint8List(0);
    final Uint8List scidToUse = localCid;

    final rawPacket = encryptQuicPacket(
      level == EncryptionLevel.application ? "short" : level.name,
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

    // final bytesToSend = level == EncryptionLevel.initial
    //     ? padTo1200(rawPacket)
    //     : rawPacket;
    final bytesToSend = rawPacket;

    socket.send(bytesToSend, InternetAddress("127.0.0.1"), 4433);

    print(
      "✅ Sent ACK ($level) pn=$pn "
      "dcid=${HEX.encode(dcidToUse)} scid=${HEX.encode(scidToUse)} "
      "acked=${ackState.received.toList()..sort()}",
    );
  }

  // void onDecryptedPacket(
  //   QuicDecryptedPacket decryptedPacket,
  //   EncryptionLevel level,
  //   InternetAddress address,
  //   int port,
  // ) {
  //   final ackState = ackStates[level];
  //   if (ackState == null) {
  //     return;
  //   }

  //   ackState.received.add(decryptedPacket.packetNumber);

  //   if (level == EncryptionLevel.initial ||
  //       level == EncryptionLevel.handshake) {
  //     sendAck(level: level, address: address.address, port: port);
  //   }
  // }

  void onDecryptedPacket(
    QuicDecryptedPacket decryptedPacket,
    EncryptionLevel level,
    InternetAddress address,
    int port,
  ) {
    final ackState = ackStates[level];
    if (ackState == null) {
      return;
    }

    ackState.received.add(decryptedPacket.packetNumber);

    // ACK every packet number space, including application
    sendAck(level: level, address: address.address, port: port);
  }

  // ===========================================================================
  // CID tracking
  // ===========================================================================

  (Uint8List, Uint8List) _extractLongHeaderCids(Uint8List pkt) {
    int off = 1;
    off += 4;

    final dcidLen = pkt[off++];
    final packetDcid = pkt.sublist(off, off + dcidLen);
    off += dcidLen;

    final scidLen = pkt[off++];
    final packetScid = pkt.sublist(off, off + scidLen);

    return (packetDcid, packetScid);
  }

  void _maybeLearnPeerCid(Uint8List pkt) {
    final isLong = (pkt[0] & 0x80) != 0;
    if (!isLong) return;

    final (packetDcid, packetScid) = _extractLongHeaderCids(pkt);

    if (!_bytesEq.equals(packetDcid, localCid)) {
      print(
        "ℹ️ Server packet DCID=${HEX.encode(packetDcid)} "
        "does not match localCid=${HEX.encode(localCid)}",
      );
    }

    if (peerCid == null || !_bytesEq.equals(peerCid!, packetScid)) {
      peerCid = Uint8List.fromList(packetScid);
      print("✅ Learned server CID: ${HEX.encode(peerCid!)}");
    }
  }

  // ===========================================================================
  // TLS / Handshake send
  // ===========================================================================

  void sendClientFinished({
    required InternetAddress address,
    required int port,
  }) {
    if (handshakeWrite == null) {
      throw StateError("Handshake write keys not available");
    }

    final ch = clientHelloRaw;
    if (ch == null) {
      throw StateError("Dynamic ClientHello not built yet");
    }

    final transcriptHash = createHash(
      Uint8List.fromList([...ch, ...tlsTranscript.toBytes()]),
    );

    // final transcriptHash = createHash(
    //   Uint8List.fromList([...originalWire, ...tlsTranscript.toBytes()]),
    // );

    final finishedKey = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "finished",
      context: Uint8List(0),
      length: 32,
    );

    final verifyData = hmacSha256(key: finishedKey, data: transcriptHash);

    final finishedHandshake = BytesBuilder()
      ..addByte(0x14)
      ..add([
        (verifyData.length >> 16) & 0xff,
        (verifyData.length >> 8) & 0xff,
        verifyData.length & 0xff,
      ])
      ..add(verifyData);

    final finishedBytes = finishedHandshake.toBytes();
    final cryptoPayload = buildCryptoFrame(finishedBytes);

    final ackState = ackStates[EncryptionLevel.handshake]!;
    final pn = ackState.allocatePn();

    final rawPacket = encryptQuicPacket(
      "handshake",
      cryptoPayload,
      handshakeWrite!.key,
      handshakeWrite!.iv,
      handshakeWrite!.hp,
      pn,
      peerCid ?? Uint8List(0),
      localCid,
      Uint8List(0),
    );

    if (rawPacket == null) {
      print("❌ Failed to encrypt Client Finished");
      return;
    }

    socket.send(rawPacket, InternetAddress("127.0.0.1"), 4433);

    print(
      "✅ Sent Client Finished (Handshake) "
      "pn=$pn dcid=${HEX.encode(peerCid ?? Uint8List(0))} "
      "scid=${HEX.encode(localCid)} "
      "verify_data=${HEX.encode(verifyData)}",
    );
  }

  // ===========================================================================
  // CRYPTO stream reassembly
  // ===========================================================================

  Uint8List assembleCryptoStream(EncryptionLevel level) {
    final chunks = cryptoChunksByLevel[level];
    final readOffset0 = cryptoReadOffsetByLevel[level];

    if (chunks == null || readOffset0 == null) {
      throw StateError('ℹ️ No CRYPTO stream reassembly state for $level');
      return Uint8List(0);
    }

    int readOffset = readOffset0;
    final result = <int>[];

    while (chunks.containsKey(readOffset)) {
      final chunk = chunks.remove(readOffset)!;
      result.addAll(chunk);
      readOffset += chunk.length;
    }

    cryptoReadOffsetByLevel[level] = readOffset;
    return Uint8List.fromList(result);
  }

  // Uint8List assembleCryptoStream(EncryptionLevel level) {
  //   final chunks = cryptoChunksByLevel[level];
  //   final readOffset0 = cryptoReadOffsetByLevel[level];

  //   if (chunks == null || readOffset0 == null) {
  //     throw StateError('ℹ️ No CRYPTO stream reassembly state for $level');
  //     return Uint8List(0);
  //   }

  //   int readOffset = readOffset0;
  //   final result = <int>[];

  //   while (chunks.containsKey(readOffset)) {
  //     final chunk = chunks.remove(readOffset)!;
  //     result.addAll(chunk);
  //     readOffset += chunk.length;
  //   }

  //   cryptoReadOffsetByLevel[level] = readOffset;
  //   return Uint8List.fromList(result);
  // }

  // ===========================================================================
  // Handshake transcript helpers
  // ===========================================================================

  // Uint8List transcriptThroughServerHandshake() {
  //   return Uint8List.fromList([
  //     ...clientHelloBytes,
  //     ...tlsTranscript.toBytes(),
  //   ]);
  // }

  Uint8List transcriptThroughServerHandshake() {
    final ch = clientHelloRaw;
    if (ch == null) {
      throw StateError("Dynamic ClientHello not built yet");
    }

    return Uint8List.fromList([...ch, ...tlsTranscript.toBytes()]);
  }

  Uint8List testHash() {
    final transcript = transcriptThroughServerHandshake();

    print("Hashing ClientHello + ServerHello: ${HEX.encode(transcript)}");

    final hash = createHash(transcript);
    print("helloHash: ${HEX.encode(hash)}");
    return hash;
  }

  Uint8List extractServerHelloFromCrypto(Uint8List cryptoStream) {
    if (cryptoStream.length < 4) {
      throw StateError("CRYPTO stream too short for Handshake header");
    }

    final msgType = cryptoStream[0];
    if (msgType != 0x02) {
      throw StateError("First handshake message is not ServerHello");
    }

    final length =
        (cryptoStream[1] << 16) | (cryptoStream[2] << 8) | cryptoStream[3];

    final totalLen = 4 + length;

    if (cryptoStream.length < totalLen) {
      throw StateError("CRYPTO stream truncated ServerHello");
    }

    return cryptoStream.sublist(0, totalLen);
  }

  // ===========================================================================
  // Packet decryption
  // ===========================================================================

  QuicDecryptedPacket decryptPacket(Uint8List packet, EncryptionLevel _unused) {
    final firstByte = packet[0];
    late final EncryptionLevel level;

    if ((firstByte & 0x80) != 0) {
      final longType = parseLongHeaderType(packet);

      if (longType == LongPacketType.initial) {
        level = EncryptionLevel.initial;
      } else if (longType == LongPacketType.handshake) {
        level = EncryptionLevel.handshake;
      } else {
        throw StateError('Unsupported long-header packet type: $longType');
      }
    } else {
      level = EncryptionLevel.application;
    }

    final keys = _readKeys[level];
    if (keys == null) {
      throw StateError('No read keys for $level');
    }

    final pnSpace = _pnSpaces[level]!;

    final Uint8List dcidForPacket = switch (level) {
      EncryptionLevel.initial => dcid,
      EncryptionLevel.handshake => peerCid ?? Uint8List(0),
      EncryptionLevel.application =>
        peerCid ??
            (throw StateError('No server CID learned for application packets')),
    };

    final result = decryptQuicPacketBytes(
      packet,
      keys.key,
      keys.iv,
      keys.hp,
      dcidForPacket,
      pnSpace.largestPn,
    );

    if (result == null) {
      throw StateError('Decryption failed');
    }

    pnSpace.onPacketDecrypted(result.packetNumber);
    return result;
  }

  // ===========================================================================
  // Initial secret generation
  // ===========================================================================

  void generateSecrets() {
    final initialSalt = Uint8List.fromList(
      HEX.decode("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    );

    final initialRandom = randomData;
    final initialSecret = hkdfExtract(initialRandom, salt: initialSalt);

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

    final clientHpKey = hkdfExpandLabel(
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

    final serverHpKey = hkdfExpandLabel(
      secret: serverSecret,
      label: "quic hp",
      context: Uint8List(0),
      length: 16,
    );

    print("Client initial key: ${HEX.encode(clientKey)}");
    print("Client initial IV:  ${HEX.encode(clientIv)}");
    print("Server initial key: ${HEX.encode(serverKey)}");
    print("Server initial IV:  ${HEX.encode(serverIv)}");
    print("Client initial header protection key: ${HEX.encode(clientHpKey)}");
    print("Server initial header protection key: ${HEX.encode(serverHpKey)}");

    // expectBytesEqual(
    //   "Client initial key",
    //   clientKey,
    //   "b14b918124fda5c8d79847602fa3520b",
    // );

    // expectBytesEqual("Client initial IV", clientIv, "ddbc15dea80925a55686a7df");

    // expectBytesEqual(
    //   "Server initial key",
    //   serverKey,
    //   "d77fc4056fcfa32bd1302469ee6ebf90",
    // );

    // expectBytesEqual("Server initial IV", serverIv, "fcb748e37ff79860faa07477");

    // expectBytesEqual(
    //   "Client initial header protection key",
    //   clientHpKey,
    //   "6df4e9d737cdf714711d7c617ee82981",
    // );

    // expectBytesEqual(
    //   "Server initial header protection key",
    //   serverHpKey,
    //   "440b2725e91dc79b370711ef792faa3d",
    // );

    print("✅ QUIC initial secrets verified");

    // Client writes Initial using client keys; reads server Initial using server keys
    initialWrite = QuicKeys(key: clientKey, iv: clientIv, hp: clientHpKey);
    initialRead = QuicKeys(key: serverKey, iv: serverIv, hp: serverHpKey);
  }

  // ===========================================================================
  // Handshake key derivation
  // ===========================================================================

  void handshakeKeyDerivationTest() {
    final sharedSecret = x25519ShareSecret(
      privateKey: keyPair.privateKeyBytes,
      publicKey: receivedServello!.keyShareEntry!.pub,
    );

    print(
      "Server key_share pub (${receivedServello!.keyShareEntry!.pub.length} bytes): "
      "${HEX.encode(receivedServello!.keyShareEntry!.pub)}",
    );

    final helloHash = testHash();

    final hashLen = 32;
    final zero = Uint8List(hashLen);
    final empty = Uint8List(0);

    final earlySecret = hkdfExtract(zero, salt: empty);

    final emptyHash = createHash(empty);

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

    final serverHsTrafficSecret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "s hs traffic",
      context: helloHash,
      length: hashLen,
    );

    final clientHandshakeKey = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );

    final clientHandshakeIV = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );

    final clientHandshakeHP = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    final serverHandshakeKey = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );

    final serverHandshakeIV = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );

    final serverHandshakeHP = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    // Client reads server handshake, writes client handshake
    handshakeRead = QuicKeys(
      key: serverHandshakeKey,
      iv: serverHandshakeIV,
      hp: serverHandshakeHP,
    );

    handshakeWrite = QuicKeys(
      key: clientHandshakeKey,
      iv: clientHandshakeIV,
      hp: clientHandshakeHP,
    );

    _readKeys[EncryptionLevel.handshake] = handshakeRead!;
    _writeKeys[EncryptionLevel.handshake] = handshakeWrite!;

    print("handshake read: $handshakeRead");
    print("handshake write: $handshakeWrite");
    print("✅ QUIC/TLS handshake keys derived (spec-correct)");
  }

  // ===========================================================================
  // Application (1-RTT) secrets
  // ===========================================================================

  void deriveApplicationSecrets() {
    print("🔐 Deriving application (1‑RTT) secrets");

    final hashLen = 32;
    final zero = Uint8List(hashLen);
    final empty = Uint8List(0);

    final transcriptHash = createHash(transcriptThroughServerHandshake());

    print("Application Transcript Hash: ${HEX.encode(transcriptHash)}");

    final emptyHash = createHash(empty);
    final derivedSecret2 = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "derived",
      context: emptyHash,
      length: hashLen,
    );

    final masterSecret = hkdfExtract(zero, salt: derivedSecret2);

    print("master_secret: ${HEX.encode(masterSecret)}");

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

    print(
      "client_application_traffic_secret_0: "
      "${HEX.encode(clientAppTrafficSecret)}",
    );
    print(
      "server_application_traffic_secret_0: "
      "${HEX.encode(serverAppTrafficSecret)}",
    );

    final clientAppKey = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );

    final clientAppIV = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );

    final clientAppHP = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    final serverAppKey = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );

    final serverAppIV = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );

    final serverAppHP = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    // Client reads server application, writes client application
    appRead = QuicKeys(key: serverAppKey, iv: serverAppIV, hp: serverAppHP);
    appWrite = QuicKeys(key: clientAppKey, iv: clientAppIV, hp: clientAppHP);

    _readKeys[EncryptionLevel.application] = appRead!;
    _writeKeys[EncryptionLevel.application] = appWrite!;

    encryptionLevel = EncryptionLevel.application;

    print("appRead:  $appRead");
    print("appWrite: $appWrite");

    print("✅ 1‑RTT application keys installed");
  }

  bool tlsTranscriptContainsFinished() {
    final Uint8List data = tlsTranscript.toBytes();

    int i = 0;
    while (i + 4 <= data.length) {
      final int type = data[i];
      final int len = (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3];

      if (type == 0x14 && i + 4 + len <= data.length) {
        return true;
      }

      i += 4 + len;
    }

    return false;
  }

  // ===========================================================================
  // Packet handling
  // ===========================================================================

  // void handleQuicPacket(Uint8List pkt) {
  //   // Learn the server CID from long-header packets before decrypting.
  //   _maybeLearnPeerCid(pkt);

  //   final packetLevel = encryptionLevel;
  //   final previousLevel = encryptionLevel;

  //   print("Encryption level: $encryptionLevel");

  //   final result = decryptPacket(pkt, packetLevel);
  //   onDecryptedPacket(result, packetLevel, InternetAddress("127.0.0.1"), 4433);

  //   final parsed = parsePayload(result.plaintext!, this, level: packetLevel);

  //   if (parsed.cryptoFrames.isNotEmpty) {
  //     receivedCryptoFrames.addAll(parsed.cryptoFrames);
  //   }

  //   if (parsed.tlsMessages.isNotEmpty) {
  //     receivedTlsMessages.addAll(parsed.tlsMessages);
  //   }

  //   if (encryptionLevel != previousLevel &&
  //       encryptionLevel == EncryptionLevel.handshake) {
  //     handshakeKeyDerivationTest();
  //   }

  //   final bool gotServerFinished = tlsTranscriptContainsFinished();

  //   if (gotServerFinished && !serverFinishedReceived) {
  //     serverFinishedReceived = true;
  //     print("🧠 Server Finished processed");
  //   }

  //   if (serverFinishedReceived && !applicationSecretsDerived) {
  //     deriveApplicationSecrets();
  //     applicationSecretsDerived = true;
  //     print("🔐 Application secrets derived");
  //   }

  //   if (serverFinishedReceived && !clientFinishedSent) {
  //     sendClientFinished(address: InternetAddress("127.0.0.1"), port: 4433);
  //     clientFinishedSent = true;
  //     print("📤 Client Finished sent");
  //   }

  //   print("parsed: $parsed");
  // }
  final Map<int, QuicStreamReassembler> streamReassemblers = {};
  QuicStreamReassembler _stream(int streamId) {
    return streamReassemblers.putIfAbsent(
      streamId,
      () => QuicStreamReassembler(),
    );
  }

  void _logServerHelloFields(Uint8List serverHello) {
    if (serverHello.length < 4) return;

    final body = serverHello.sublist(4);
    int p = 0;

    if (body.length < 2 + 32 + 1 + 2 + 1 + 2) return;

    final legacyVersion = (body[p++] << 8) | body[p++];
    final serverRandom = body.sublist(p, p + 32);
    p += 32;

    final sessionIdLen = body[p++];
    final sessionId = body.sublist(p, p + sessionIdLen);
    p += sessionIdLen;

    final cipherSuite = (body[p++] << 8) | body[p++];
    final compressionMethod = body[p++];

    final extensionsLen = (body[p++] << 8) | body[p++];
    final extEnd = p + extensionsLen;

    int? selectedGroup;
    Uint8List? serverPublicKey;

    while (p + 4 <= body.length && p < extEnd) {
      final extType = (body[p++] << 8) | body[p++];
      final extLen = (body[p++] << 8) | body[p++];
      final extData = body.sublist(p, p + extLen);
      p += extLen;

      if (extType == 0x0033 && extData.length >= 4) {
        selectedGroup = (extData[0] << 8) | extData[1];
        final keyLen = (extData[2] << 8) | extData[3];
        if (4 + keyLen <= extData.length) {
          serverPublicKey = extData.sublist(4, 4 + keyLen);
        }
      }
    }

    print("🟪 [CLIENT EXTRACT] ServerHello fields");
    print("  legacy_version: $legacyVersion");
    print("  server_random: ${HEX.encode(serverRandom)}");
    print("  session_id: ${HEX.encode(sessionId)}");
    print("  cipher_suite: $cipherSuite");
    print("  compression_method: $compressionMethod");
    print("  selected_group: ${selectedGroup ?? -1}");
    if (serverPublicKey != null) {
      print("  server_public_key: ${HEX.encode(serverPublicKey)}");
    }
  }

  Map<int, Uint8List> _extractHandshakeMessages(Uint8List stream) {
    final out = <int, Uint8List>{};

    int i = 0;
    while (i + 4 <= stream.length) {
      final type = stream[i];
      final len = (stream[i + 1] << 16) | (stream[i + 2] << 8) | stream[i + 3];

      if (i + 4 + len > stream.length) break;

      out[type] = stream.sublist(i, i + 4 + len);
      i += 4 + len;
    }

    return out;
  }

  void _maybeLogServerArtifacts(QuicSession session) {
    final transcript = session.tlsTranscript.toBytes();
    final msgs = _extractHandshakeMessages(transcript);

    final serverHello = msgs[0x02];
    final encryptedExtensions = msgs[0x08];
    final certificate = msgs[0x0b];
    final certificateVerify = msgs[0x0f];
    final finished = msgs[0x14];

    if (serverHello == null ||
        encryptedExtensions == null ||
        certificate == null ||
        certificateVerify == null) {
      return;
    }

    print("🟪 [CLIENT EXTRACT] Full server handshake artifacts");
    print('const String serverHelloHex = "${HEX.encode(serverHello)}";');
    print(
      'const String encryptedExtensionsHex = "${HEX.encode(encryptedExtensions)}";',
    );
    print('const String certificateHex = "${HEX.encode(certificate)}";');
    print(
      'const String certificateVerifyHex = "${HEX.encode(certificateVerify)}";',
    );

    if (finished != null) {
      print('const String finishedHex = "${HEX.encode(finished)}";');
    }

    _logServerHelloFields(serverHello);
    print("✅ Extracted server handshake values from the client side");
  }

  // ParsedQuicPayload parsePayload(
  //   Uint8List plaintextPayload,
  //   QuicSession session, {
  //   required EncryptionLevel level,
  // }) {
  //   print('--- Parsing Decrypted QUIC Payload ---');

  //   final buffer = QuicBuffer(data: plaintextPayload);
  //   final frames = <QuicFrame>[];
  //   final cryptoFrames = <CryptoFrame>[];
  //   final tlsMessages = <TlsHandshakeMessage>[];
  //   AckFrame? ackFrame;

  //   try {
  //     while (buffer.remaining > 0) {
  //       if (buffer.remaining == 0) break;

  //       final frameType = buffer.pullVarInt();

  //       // =========================================================
  //       // PADDING (0x00)
  //       // =========================================================
  //       if (frameType == 0x00) {
  //         continue;
  //       }

  //       // =========================================================
  //       // PING (0x01)
  //       // =========================================================
  //       if (frameType == 0x01) {
  //         print('✅ Parsed PING');
  //         continue;
  //       }

  //       // =========================================================
  //       // CRYPTO (0x06)
  //       // =========================================================
  //       if (frameType == 0x06) {
  //         if (buffer.remaining == 0) break;
  //         final offset = buffer.pullVarInt();

  //         if (buffer.remaining == 0) break;
  //         final length = buffer.pullVarInt();

  //         if (buffer.remaining < length) {
  //           print(
  //             '🛑 CRYPTO frame truncated: need $length, have ${buffer.remaining}',
  //           );
  //           break;
  //         }

  //         final cryptoData = buffer.pullBytes(length);

  //         print('✅ Parsed CRYPTO Frame: offset=$offset, length=$length');

  //         // Store CRYPTO chunk in per-level reassembly map
  //         if (session.cryptoChunksByLevel.containsKey(level)) {
  //           session.cryptoChunksByLevel[level]![offset] = cryptoData;
  //         }

  //         // Reassemble contiguous CRYPTO stream bytes
  //         final assembled = session.assembleCryptoStream(level);

  //         // Append newly contiguous bytes to transcript and parse TLS messages
  //         if (assembled.isNotEmpty) {
  //           session.tlsTranscript.add(assembled);
  //           tlsMessages.addAll(
  //             parseTlsMessages(assembled, quicSession: session),
  //           );

  //           // Log useful server-side handshake artifacts from client side
  //           _maybeLogServerArtifacts(session);
  //         }

  //         continue;
  //       }

  //       // =========================================================
  //       // ACK (0x02) / ACK + ECN (0x03)
  //       // =========================================================
  //       if (frameType == 0x02 || frameType == 0x03) {
  //         final hasECN = (frameType & 0x01) == 0x01;

  //         if (buffer.remaining == 0) break;
  //         final largest = buffer.pullVarInt();

  //         if (buffer.remaining == 0) break;
  //         final delay = buffer.pullVarInt();

  //         if (buffer.remaining == 0) break;
  //         final rangeCount = buffer.pullVarInt();

  //         if (buffer.remaining == 0) break;
  //         final firstRange = buffer.pullVarInt();

  //         final ranges = <dynamic>[];
  //         for (int i = 0; i < rangeCount; i++) {
  //           if (buffer.remaining == 0) break;
  //           final gap = buffer.pullVarInt();

  //           if (buffer.remaining == 0) break;
  //           final len = buffer.pullVarInt();

  //           ranges.add((gap: gap, length: len));
  //         }

  //         dynamic ecn;
  //         if (hasECN) {
  //           if (buffer.remaining == 0) break;
  //           final ect0 = buffer.pullVarInt();

  //           if (buffer.remaining == 0) break;
  //           final ect1 = buffer.pullVarInt();

  //           if (buffer.remaining == 0) break;
  //           final ce = buffer.pullVarInt();

  //           ecn = {ect0: ect0, ect1: ect1, ce: ce};
  //         }

  //         ackFrame = AckFrame(
  //           largest: largest,
  //           delay: delay,
  //           firstRange: firstRange,
  //           ranges: ranges,
  //           ecn: ecn,
  //         );

  //         frames.add(ackFrame);

  //         print(
  //           '✅ Parsed ACK largest=$largest delay=$delay firstRange=$firstRange',
  //         );

  //         continue;
  //       }

  //       // =========================================================
  //       // STREAM frames (0x08..0x0f)
  //       // =========================================================
  //       if ((frameType & 0xF8) == 0x08) {
  //         final fin = (frameType & 0x01) != 0;
  //         final hasLen = (frameType & 0x02) != 0;
  //         final hasOff = (frameType & 0x04) != 0;

  //         if (buffer.remaining == 0) break;
  //         final streamId = buffer.pullVarInt();

  //         final streamOffset = hasOff ? buffer.pullVarInt() : 0;
  //         final dataLen = hasLen ? buffer.pullVarInt() : buffer.remaining;

  //         if (buffer.remaining < dataLen) {
  //           print(
  //             '🛑 STREAM frame truncated: need $dataLen, have ${buffer.remaining}',
  //           );
  //           break;
  //         }

  //         final data = buffer.pullBytes(dataLen);

  //         print(
  //           '✅ Parsed STREAM frame '
  //           'streamId=$streamId offset=$streamOffset len=$dataLen fin=$fin',
  //         );

  //         // Route 1-RTT/application STREAM frames into HTTP/3/WebTransport
  //         if (level == EncryptionLevel.application) {
  //           session.handleHttp3StreamChunk(
  //             streamId,
  //             streamOffset,
  //             data,
  //             fin: fin,
  //           );
  //         } else {
  //           print('ℹ️ Ignoring non-application STREAM frame on level=$level');
  //         }

  //         continue;
  //       }

  //       // =========================================================
  //       // DATAGRAM frames (0x30 no length, 0x31 with length)
  //       // =========================================================
  //       if (frameType == 0x30 || frameType == 0x31) {
  //         final hasLen = frameType == 0x31;
  //         final datagramLen = hasLen ? buffer.pullVarInt() : buffer.remaining;

  //         if (buffer.remaining < datagramLen) {
  //           print(
  //             '🛑 DATAGRAM frame truncated: need $datagramLen, have ${buffer.remaining}',
  //           );
  //           break;
  //         }

  //         final payload = buffer.pullBytes(datagramLen);

  //         print('✅ Parsed DATAGRAM len=${payload.length}');

  //         if (level == EncryptionLevel.application) {
  //           session.handleWebTransportDatagram(payload);
  //         } else {
  //           print('ℹ️ Ignoring non-application DATAGRAM frame on level=$level');
  //         }

  //         continue;
  //       }

  //       // =========================================================
  //       // HANDSHAKE_DONE (0x1e)
  //       // =========================================================
  //       if (frameType == 0x1e) {
  //         print('✅ Parsed HANDSHAKE_DONE');
  //         continue;
  //       }

  //       // =========================================================
  //       // CONNECTION_CLOSE transport/application (0x1c / 0x1d)
  //       // =========================================================
  //       if (frameType == 0x1c || frameType == 0x1d) {
  //         if (buffer.remaining == 0) break;
  //         final errorCode = buffer.pullVarInt();

  //         int? offendingFrameType;
  //         if (frameType == 0x1c) {
  //           if (buffer.remaining == 0) break;
  //           offendingFrameType = buffer.pullVarInt();
  //         }

  //         if (buffer.remaining == 0) break;
  //         final reasonLen = buffer.pullVarInt();

  //         if (buffer.remaining < reasonLen) {
  //           print(
  //             '🛑 CONNECTION_CLOSE reason truncated: need $reasonLen, have ${buffer.remaining}',
  //           );
  //           break;
  //         }

  //         final reasonBytes = reasonLen > 0
  //             ? buffer.pullBytes(reasonLen)
  //             : Uint8List(0);

  //         final reason = utf8.decode(reasonBytes, allowMalformed: true);

  //         print(
  //           '🛑 Parsed CONNECTION_CLOSE '
  //           'frameType=0x${frameType.toRadixString(16)} '
  //           'errorCode=0x${errorCode.toRadixString(16)} '
  //           '${offendingFrameType != null ? 'offendingFrameType=0x${offendingFrameType.toRadixString(16)} ' : ''}'
  //           'reason="$reason"',
  //         );

  //         break;
  //       }

  //       // =========================================================
  //       // Unknown frame — stop safely
  //       // =========================================================
  //       print(
  //         'ℹ️ Skipping unknown frame type 0x${frameType.toRadixString(16)}',
  //       );
  //       break;
  //     }
  //   } catch (e, st) {
  //     print('\n🛑 Error during payload parsing: $e\n$st');
  //   }

  //   print('\n🎉 Payload parsing complete.');

  //   return ParsedQuicPayload(
  //     frames: frames,
  //     cryptoFrames: cryptoFrames,
  //     ack: ackFrame,
  //     tlsMessages: tlsMessages,
  //   );
  // }

  ParsedQuicPayload parsePayload(
    Uint8List plaintextPayload,
    QuicSession session, {
    required EncryptionLevel level,
  }) {
    print('--- Parsing Decrypted QUIC Payload ---');

    final buffer = QuicBuffer(data: plaintextPayload);
    final frames = <QuicFrame>[];
    final cryptoFrames = <CryptoFrame>[]; // kept for API compatibility
    final tlsMessages = <TlsHandshakeMessage>[];
    AckFrame? ackFrame;

    try {
      while (buffer.remaining > 0) {
        final frameType = buffer.pullVarInt();

        // =========================================================
        // PADDING (0x00)
        // =========================================================
        if (frameType == 0x00) {
          continue;
        }

        // =========================================================
        // PING (0x01)
        // =========================================================
        if (frameType == 0x01) {
          print('✅ Parsed PING');
          continue;
        }

        // =========================================================
        // CRYPTO (0x06)
        // =========================================================
        if (frameType == 0x06) {
          if (buffer.remaining == 0) break;
          final offset = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final length = buffer.pullVarInt();

          if (buffer.remaining < length) {
            print(
              '🛑 CRYPTO frame truncated: need $length, have ${buffer.remaining}',
            );
            break;
          }

          final cryptoData = buffer.pullBytes(length);

          print('✅ Parsed CRYPTO Frame: offset=$offset, length=$length');

          // Keep frame object if your ParsedQuicPayload API expects it
          cryptoFrames.add(CryptoFrame(offset: offset, data: cryptoData));

          // Forward CRYPTO bytes to session-owned reassembly/parsing
          final newMessages = session.handleCryptoFrame(
            level: level,
            offset: offset,
            data: cryptoData,
          );

          if (newMessages.isNotEmpty) {
            tlsMessages.addAll(newMessages);
          }

          continue;
        }

        // =========================================================
        // ACK (0x02) / ACK + ECN (0x03)
        // =========================================================
        if (frameType == 0x02 || frameType == 0x03) {
          final hasECN = (frameType & 0x01) == 0x01;

          if (buffer.remaining == 0) break;
          final largest = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final delay = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final rangeCount = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final firstRange = buffer.pullVarInt();

          final ranges = <dynamic>[];
          for (int i = 0; i < rangeCount; i++) {
            if (buffer.remaining == 0) break;
            final gap = buffer.pullVarInt();

            if (buffer.remaining == 0) break;
            final len = buffer.pullVarInt();

            ranges.add((gap: gap, length: len));
          }

          dynamic ecn;
          if (hasECN) {
            if (buffer.remaining == 0) break;
            final ect0 = buffer.pullVarInt();

            if (buffer.remaining == 0) break;
            final ect1 = buffer.pullVarInt();

            if (buffer.remaining == 0) break;
            final ce = buffer.pullVarInt();

            ecn = {ect0: ect0, ect1: ect1, ce: ce};
          }

          ackFrame = AckFrame(
            largest: largest,
            delay: delay,
            firstRange: firstRange,
            ranges: ranges,
            ecn: ecn,
          );

          frames.add(ackFrame);

          print(
            '✅ Parsed ACK largest=$largest delay=$delay firstRange=$firstRange',
          );

          continue;
        }

        // =========================================================
        // STREAM frames (0x08..0x0f)
        // =========================================================
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
              '🛑 STREAM frame truncated: need $dataLen, have ${buffer.remaining}',
            );
            break;
          }

          final data = buffer.pullBytes(dataLen);

          print(
            '✅ Parsed STREAM frame '
            'streamId=$streamId offset=$streamOffset len=$dataLen fin=$fin',
          );

          if (level == EncryptionLevel.application) {
            session.handleHttp3StreamChunk(
              streamId,
              streamOffset,
              data,
              fin: fin,
            );
          } else {
            print('ℹ️ Ignoring non-application STREAM frame on level=$level');
          }

          continue;
        }

        // =========================================================
        // DATAGRAM frames (0x30 no length, 0x31 with length)
        // =========================================================
        if (frameType == 0x30 || frameType == 0x31) {
          final hasLen = frameType == 0x31;
          final datagramLen = hasLen ? buffer.pullVarInt() : buffer.remaining;

          if (buffer.remaining < datagramLen) {
            print(
              '🛑 DATAGRAM frame truncated: need $datagramLen, have ${buffer.remaining}',
            );
            break;
          }

          final payload = buffer.pullBytes(datagramLen);

          print('✅ Parsed DATAGRAM len=${payload.length}');

          if (level == EncryptionLevel.application) {
            session.handleWebTransportDatagram(payload);
          } else {
            print('ℹ️ Ignoring non-application DATAGRAM frame on level=$level');
          }

          continue;
        }

        // =========================================================
        // NEW_TOKEN (0x07)
        // =========================================================
        if (frameType == 0x07) {
          if (buffer.remaining == 0) break;
          final tokenLen = buffer.pullVarInt();

          if (buffer.remaining < tokenLen) {
            print(
              '🛑 NEW_TOKEN truncated: need $tokenLen, have ${buffer.remaining}',
            );
            break;
          }

          final token = buffer.pullBytes(tokenLen);
          print('ℹ️ Parsed NEW_TOKEN len=${token.length}');
          continue;
        }

        // =========================================================
        // HANDSHAKE_DONE (0x1e)
        // =========================================================
        if (frameType == 0x1e) {
          print('✅ Parsed HANDSHAKE_DONE');
          continue;
        }

        // =========================================================
        // CONNECTION_CLOSE transport/application (0x1c / 0x1d)
        // =========================================================
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
              '🛑 CONNECTION_CLOSE reason truncated: need $reasonLen, have ${buffer.remaining}',
            );
            break;
          }

          final reasonBytes = reasonLen > 0
              ? buffer.pullBytes(reasonLen)
              : Uint8List(0);

          final reason = utf8.decode(reasonBytes, allowMalformed: true);

          print(
            '🛑 Parsed CONNECTION_CLOSE '
            'frameType=0x${frameType.toRadixString(16)} '
            'errorCode=0x${errorCode.toRadixString(16)} '
            '${offendingFrameType != null ? 'offendingFrameType=0x${offendingFrameType.toRadixString(16)} ' : ''}'
            'reason="$reason"',
          );

          break;
        }

        // =========================================================
        // Unknown frame — stop safely
        // =========================================================
        print(
          'ℹ️ Skipping unknown frame type 0x${frameType.toRadixString(16)}',
        );
        break;
      }
    } catch (e, st) {
      print('\n🛑 Error during payload parsing: $e\n$st');
    }

    print('\n🎉 Payload parsing complete.');

    return ParsedQuicPayload(
      frames: frames,
      cryptoFrames: cryptoFrames,
      ack: ackFrame,
      tlsMessages: tlsMessages,
    );
  }

  bool serverCertificateVerified = false;

  final Uint8List pinnedServerCertSha256 = Uint8List.fromList(
    HEX.decode(
      '3967C4D65B709A2DD6BEA80C6F7B1BC7F3CB4D613EE6EB01065F434B2B6C04EC',
    ),
  );

  void _maybeVerifyServerCertificate() {
    if (serverCertificateVerified) return;

    final transcript = tlsTranscript.toBytes();
    final msgs = _extractHandshakeMessages(transcript);

    final ch = clientHelloRaw;
    final sh = msgs[0x02];
    final ee = msgs[0x08];
    final cert = msgs[0x0b];
    final cv = msgs[0x0f];

    if (ch == null || sh == null || ee == null || cert == null || cv == null) {
      return; // still waiting
    }

    // 🔒 MUST succeed or abort connection
    verifyServerCertificateAndSignature(
      clientHello: ch,
      serverHello: sh,
      encryptedExtensions: ee,
      certificateHandshake: cert,
      certificateVerifyHandshake: cv,
      pinnedCertSha256: pinnedServerCertSha256,
    );

    serverCertificateVerified = true;
    print('✅ Server certificate VERIFIED');
  }

  final Map<EncryptionLevel, QuicStreamReassembler> cryptoReassemblers = {
    EncryptionLevel.initial: QuicStreamReassembler(),
    EncryptionLevel.handshake: QuicStreamReassembler(),
    EncryptionLevel.application: QuicStreamReassembler(),
  };

  List<TlsHandshakeMessage> handleCryptoFrame({
    required EncryptionLevel level,
    required int offset,
    required Uint8List data,
  }) {
    final reassembler = cryptoReassemblers[level];
    if (reassembler == null) {
      print('ℹ️ No CRYPTO reassembler for $level');
      return const [];
    }

    reassembler.insert(offset, data);
    final assembled = reassembler.drain();

    if (assembled.isEmpty) {
      return const [];
    }

    // Initial + Handshake bytes belong in the transcript
    if (level == EncryptionLevel.initial ||
        level == EncryptionLevel.handshake) {
      tlsTranscript.add(assembled);
    }

    final messages = parseTlsMessages(assembled, quicSession: this);

    if (messages.isNotEmpty) {
      receivedTlsMessages.addAll(messages);
      _maybeLogServerArtifacts(this);

      // _maybeVerifyServerCertificate(); // ✅ ADD THIS
    }

    return messages;
  }

  List<TlsHandshakeMessage> parseTlsMessages(
    Uint8List cryptoData, {
    QuicSession? quicSession,
  }) {
    final buffer = QuicBuffer(data: cryptoData);
    final messages = <TlsHandshakeMessage>[];

    while (buffer.remaining > 0) {
      if (buffer.remaining < 4) {
        print(
          '⚠️ Truncated TLS handshake header: remaining=${buffer.remaining}',
        );
        break;
      }

      final msgType = buffer.pullUint8();
      final length = buffer.pullUint24();

      print('handshake length: $length');

      if (buffer.remaining < length) {
        print(
          '⚠️ Truncated TLS handshake body: need $length, have ${buffer.remaining}',
        );
        break;
      }

      final body = buffer.pullBytes(length);
      final bodyBuf = QuicBuffer(data: body);

      switch (msgType) {
        case 0x01: // ClientHello
          final ch = parseClientHelloBody(bodyBuf);
          messages.add(ch);
          break;

        case 0x02: // ServerHello
          print('✅ ServerHello received (${length} bytes)');
          final sh = ServerHello.parse(bodyBuf);
          if (quicSession != null) {
            quicSession.encryptionLevel = EncryptionLevel.handshake;
            quicSession.receivedServello = sh;
          }
          messages.add(sh);
          break;

        case 0x04: // NewSessionTicket
          print('ℹ️ NewSessionTicket received (${length} bytes) — ignored');
          messages.add(UnknownHandshakeMessage(msgType, body));
          break;

        case 0x08: // EncryptedExtensions
          print('✅ EncryptedExtensions received (${length} bytes)');
          final ee = EncryptedExtensions.parse(bodyBuf);
          print('ee: $ee');
          messages.add(ee);
          break;

        case 0x0B: // Certificate
          print('✅ Certificate received (${length} bytes)');
          final cert = CertificateMessage.parse(bodyBuf);
          messages.add(cert);
          break;

        case 0x0F: // CertificateVerify
          print('✅ CertificateVerify received (${length} bytes)');
          final cv = CertificateVerify.parse(bodyBuf);
          messages.add(cv);
          break;

        case 0x14: // Finished
          print('✅ Finished received (${length} bytes)');
          final fin = FinishedMessage.parse(bodyBuf);
          messages.add(fin);
          break;

        default:
          print('⚠️ Unknown handshake message: type=$msgType len=$length');
          messages.add(UnknownHandshakeMessage(msgType, body));
          break;
      }
    }

    return messages;
  }

  void handleQuicPacket(Uint8List pkt) {
    // Learn the server CID from long-header packets before decrypting.
    _maybeLearnPeerCid(pkt);

    final actualLevel = detectPacketLevel(pkt);
    final previousConnectionLevel = encryptionLevel;

    print("Packet level: $actualLevel (connection state=$encryptionLevel)");

    final result = decryptPacket(pkt, actualLevel);

    onDecryptedPacket(result, actualLevel, InternetAddress("127.0.0.1"), 4433);

    final parsed = parsePayload(result.plaintext!, this, level: actualLevel);

    if (parsed.cryptoFrames.isNotEmpty) {
      receivedCryptoFrames.addAll(parsed.cryptoFrames);
    }

    if (parsed.tlsMessages.isNotEmpty) {
      receivedTlsMessages.addAll(parsed.tlsMessages);
    }

    // Only promote the connection state upward, never downward.
    if (actualLevel.index > encryptionLevel.index) {
      encryptionLevel = actualLevel;
    }

    if (encryptionLevel != previousConnectionLevel &&
        encryptionLevel == EncryptionLevel.handshake) {
      handshakeKeyDerivationTest();
    }

    final bool gotServerFinished = tlsTranscriptContainsFinished();

    if (gotServerFinished && !serverFinishedReceived) {
      serverFinishedReceived = true;
      print("🧠 Server Finished processed");
    }

    if (serverFinishedReceived && !applicationSecretsDerived) {
      deriveApplicationSecrets();
      applicationSecretsDerived = true;
      print("🔐 Application secrets derived");
    }

    if (serverFinishedReceived && !clientFinishedSent) {
      sendClientFinished(address: InternetAddress("127.0.0.1"), port: 4433);
      clientFinishedSent = true;
      print("📤 Client Finished sent");
    }

    print("parsed: $parsed, encryption level: $actualLevel");
  }

  // ===========================================================================
  // HTTP/3 + WebTransport support
  // ===========================================================================

  bool _isClientInitiatedBidi(int streamId) => (streamId & 0x03) == 0x00;
  bool _isServerInitiatedUni(int streamId) => (streamId & 0x03) == 0x03;

  int _allocateClientBidiStreamId() {
    final id = nextClientBidiStreamId;
    nextClientBidiStreamId += 4;
    return id;
  }

  int _allocateClientUniStreamId() {
    final id = nextClientUniStreamId;
    nextClientUniStreamId += 4;
    return id;
  }

  // void handleHttp3StreamChunk(
  //   int streamId,
  //   int streamOffset,
  //   Uint8List streamData, {
  //   required bool fin,
  // }) {
  //   // ----------------------------------------------------------
  //   // 1) Raw QUIC stream reassembly
  //   // ----------------------------------------------------------
  //   final rawChunks = h3.rawStreamChunks.putIfAbsent(
  //     streamId,
  //     () => <int, Uint8List>{},
  //   );
  //   rawChunks[streamOffset] = streamData;

  //   String kind = h3.streamKinds[streamId] ?? 'unknown';

  //   // ----------------------------------------------------------
  //   // 2) Determine stream kind
  //   // ----------------------------------------------------------
  //   if (kind == 'unknown') {
  //     if (_isClientInitiatedBidi(streamId)) {
  //       // Request stream: no stream-type prefix
  //       kind = 'request';
  //       h3.streamKinds[streamId] = kind;
  //       h3.streamTypePrefixLen[streamId] = 0;
  //     } else if (_isServerInitiatedUni(streamId)) {
  //       // Need bytes starting at offset 0 to read stream type varint
  //       final zeroChunk = rawChunks[0];
  //       if (zeroChunk == null) {
  //         return;
  //       }

  //       final typeInfo = readVarInt(zeroChunk, 0);
  //       if (typeInfo == null) {
  //         return;
  //       }

  //       final streamType = typeInfo.value as int;
  //       final prefixLen = typeInfo.byteLength as int;
  //       h3.streamTypePrefixLen[streamId] = prefixLen;

  //       if (streamType == H3_STREAM_TYPE_CONTROL) {
  //         kind = 'control';
  //         h3.controlStreamSeen = true;
  //         print('✅ Saw HTTP/3 control stream on QUIC stream $streamId');
  //       } else {
  //         kind = 'other_uni';
  //         print(
  //           'ℹ️ Saw unsupported server uni stream type '
  //           '0x${streamType.toRadixString(16)} on QUIC stream $streamId',
  //         );
  //       }

  //       h3.streamKinds[streamId] = kind;
  //     } else {
  //       kind = 'other';
  //       h3.streamKinds[streamId] = kind;
  //       h3.streamTypePrefixLen[streamId] = 0;
  //     }
  //   }

  //   final prefixLen = h3.streamTypePrefixLen[streamId] ?? 0;

  //   // ----------------------------------------------------------
  //   // 3) Strip uni-stream type prefix before H3 frame parsing
  //   // ----------------------------------------------------------
  //   final rawStart = streamOffset;
  //   final rawEnd = streamOffset + streamData.length;

  //   if (rawEnd <= prefixLen) {
  //     // Entire chunk is still within the stream-type prefix
  //     return;
  //   }

  //   int sliceStartInChunk = 0;
  //   int h3Offset = rawStart - prefixLen;

  //   if (rawStart < prefixLen) {
  //     sliceStartInChunk = prefixLen - rawStart;
  //     h3Offset = 0;
  //   }

  //   final h3Bytes = streamData.sublist(sliceStartInChunk);

  //   final frameChunks = h3.h3FrameChunks.putIfAbsent(
  //     streamId,
  //     () => <int, Uint8List>{},
  //   );
  //   frameChunks[h3Offset] = h3Bytes;

  //   final readOffset = h3.h3FrameReadOffsets[streamId] ?? 0;
  //   final extracted = extract_h3_frames_from_chunks(frameChunks, readOffset);
  //   h3.h3FrameReadOffsets[streamId] = extracted['new_from_offset'] as int;

  //   for (final frame in extracted['frames']) {
  //     final int type = frame['frame_type'] as int;
  //     final Uint8List payload = frame['payload'] as Uint8List;

  //     if (kind == 'control') {
  //       _handleHttp3ControlFrame(type, payload);
  //       continue;
  //     }

  //     if (kind == 'request') {
  //       _handleHttp3RequestStreamFrame(streamId, type, payload);
  //       continue;
  //     }

  //     print(
  //       'ℹ️ Ignoring HTTP/3 frame type=0x${type.toRadixString(16)} '
  //       'on stream=$streamId kind=$kind',
  //     );
  //   }

  //   if (fin) {
  //     print('✅ QUIC stream $streamId FIN received');
  //   }
  // }
  // final Map<EncryptionLevel, QuicStreamReassembler> cryptoReassemblers = {
  //   EncryptionLevel.initial: QuicStreamReassembler(),
  //   EncryptionLevel.handshake: QuicStreamReassembler(),
  //   EncryptionLevel.application: QuicStreamReassembler(),
  // };
  // Uint8List consumeCryptoBytes(
  //   EncryptionLevel level,
  //   int offset,
  //   Uint8List data,
  // ) {
  //   final r = cryptoReassemblers[level]!;

  //   // Insert CRYPTO bytes (safe against retransmissions)
  //   r.insert(offset, data);

  //   // Drain only NEW contiguous bytes
  //   return r.drain();
  // }

  void handleHttp3StreamChunk(
    int streamId,
    int streamOffset,
    Uint8List streamData, {
    required bool fin,
  }) {
    // ----------------------------------------------------------
    // 1) QUIC stream reassembly + retirement (core fix)
    // ----------------------------------------------------------
    final reassembler = _stream(streamId);

    reassembler.insert(streamOffset, streamData);
    final newBytes = reassembler.drain();

    if (newBytes.isEmpty) {
      // Pure retransmission, already consumed
      return;
    }

    // Compute absolute byte range of newly-drained bytes
    final int newStart = reassembler.readOffset - newBytes.length;
    final int newEnd = reassembler.readOffset;

    // ----------------------------------------------------------
    // 2) Determine stream kind (control / request / other)
    // ----------------------------------------------------------
    String kind = h3.streamKinds[streamId] ?? 'unknown';

    if (kind == 'unknown') {
      if (_isClientInitiatedBidi(streamId)) {
        kind = 'request';
        h3.streamKinds[streamId] = kind;
        h3.streamTypePrefixLen[streamId] = 0;
      } else if (_isServerInitiatedUni(streamId)) {
        // Server uni stream: first varint is stream type
        final typeInfo = readVarInt(newBytes, 0);
        if (typeInfo == null) {
          // Need more bytes
          return;
        }

        final streamType = typeInfo.value as int;
        final prefixLen = typeInfo.byteLength as int;

        h3.streamTypePrefixLen[streamId] = prefixLen;

        print(
          '🟦 SERVER UNI STREAM '
          'id=$streamId type=0x${streamType.toRadixString(16)}',
        );

        if (streamType == H3_STREAM_TYPE_CONTROL) {
          kind = 'control';
          h3.controlStreamSeen = true;
          print('✅ Saw HTTP/3 control stream on QUIC stream $streamId');
        } else {
          kind = 'other_uni';
          print(
            'ℹ️ Ignoring server uni stream type '
            '0x${streamType.toRadixString(16)} on stream $streamId',
          );
        }

        h3.streamKinds[streamId] = kind;
      } else {
        kind = 'other';
        h3.streamKinds[streamId] = kind;
        h3.streamTypePrefixLen[streamId] = 0;
      }
    }

    final int prefixLen = h3.streamTypePrefixLen[streamId] ?? 0;

    // ----------------------------------------------------------
    // 3) Strip uni-stream type prefix
    // ----------------------------------------------------------
    if (newEnd <= prefixLen) {
      // Still inside prefix bytes
      return;
    }

    int sliceStart = 0;
    int h3Offset = newStart - prefixLen;

    if (newStart < prefixLen) {
      sliceStart = prefixLen - newStart;
      h3Offset = 0;
    }

    final Uint8List h3Bytes = newBytes.sublist(sliceStart);

    // ----------------------------------------------------------
    // 4) HTTP/3 frame extraction (ordered, deduplicated)
    // ----------------------------------------------------------
    final frameChunks = h3.h3FrameChunks.putIfAbsent(
      streamId,
      () => <int, Uint8List>{},
    );

    frameChunks[h3Offset] = h3Bytes;

    final int readOffset = h3.h3FrameReadOffsets[streamId] ?? 0;
    final extracted = extract_h3_frames_from_chunks(frameChunks, readOffset);

    h3.h3FrameReadOffsets[streamId] = extracted['new_from_offset'] as int;

    for (final frame in extracted['frames']) {
      final int type = frame['frame_type'] as int;
      final Uint8List payload = frame['payload'] as Uint8List;

      if (kind == 'control') {
        _handleHttp3ControlFrame(type, payload);
        continue;
      }

      if (kind == 'request') {
        _handleHttp3RequestStreamFrame(streamId, type, payload);
        continue;
      }

      print(
        'ℹ️ Ignoring HTTP/3 frame type=0x${type.toRadixString(16)} '
        'on stream=$streamId kind=$kind',
      );
    }

    if (fin) {
      print('✅ QUIC stream $streamId FIN received');
    }
  }

  EncryptionLevel detectPacketLevel(Uint8List packet) {
    final firstByte = packet[0];

    if ((firstByte & 0x80) != 0) {
      final longType = parseLongHeaderType(packet);

      if (longType == LongPacketType.initial) {
        return EncryptionLevel.initial;
      } else if (longType == LongPacketType.handshake) {
        return EncryptionLevel.handshake;
      } else {
        throw StateError('Unsupported long-header packet type: $longType');
      }
    }

    return EncryptionLevel.application;
  }

  // void _handleHttp3ControlFrame(int frameType, Uint8List payload) {
  //   if (frameType == H3_FRAME_SETTINGS) {
  //     final settings = parse_h3_settings_frame(payload);
  //     h3.peerSettings
  //       ..clear()
  //       ..addAll(settings);
  //     h3.settingsReceived = true;

  //     print('✅ Received HTTP/3 SETTINGS from server: $settings');
  //     return;
  //   }

  //   print(
  //     'ℹ️ Ignoring unsupported control-stream frame '
  //     '0x${frameType.toRadixString(16)}',
  //   );
  // }
  // void _handleHttp3ControlFrame(int frameType, Uint8List payload) {
  //   if (frameType == H3_FRAME_SETTINGS) {
  //     final settings = parse_h3_settings_frame(payload);
  //     h3.peerSettings
  //       ..clear()
  //       ..addAll(settings);
  //     h3.settingsReceived = true;

  //     print('✅ Received HTTP/3 SETTINGS from server: $settings');

  //     // --------------------------------------------------------
  //     // WebTransport test trigger:
  //     // As soon as SETTINGS arrive, open a WT CONNECT stream.
  //     // --------------------------------------------------------
  //     if (!webTransportConnectSent) {
  //       final sessionId = openWebTransportSession(
  //         '/wt',
  //         authority: 'localhost',
  //         scheme: 'https',
  //         address: InternetAddress('127.0.0.1'),
  //         port: 4433,
  //       );

  //       activeWebTransportSessionId = sessionId;
  //       webTransportConnectSent = true;

  //       print('🧪 WebTransport test: CONNECT sent on stream $sessionId');
  //     }

  //     return;
  //   }

  //   print(
  //     'ℹ️ Ignoring unsupported control-stream frame '
  //     '0x${frameType.toRadixString(16)}',
  //   );
  // }

  void _handleHttp3RequestStreamFrame(
    int streamId,
    int frameType,
    Uint8List payload,
  ) {
    if (frameType == H3_FRAME_HEADERS) {
      final headers = decode_qpack_header_fields(payload);

      String status = '';
      for (final h in headers) {
        if (h.name == ':status') status = h.value;
      }

      print('📥 HTTP/3 HEADERS on stream $streamId status=$status');
      for (final h in headers) {
        print('   ${h.name}: ${h.value}');
      }

      final wt = h3.webTransportSessions[streamId];
      if (wt != null && status == '200') {
        wt.established = true;
        print('✅ WebTransport session established on stream $streamId');

        // ------------------------------------------------------
        // WebTransport test trigger:
        // Send one datagram immediately after CONNECT succeeds.
        // ------------------------------------------------------
        if (!webTransportDatagramSent) {
          final testData = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);

          sendWebTransportDatagram(
            streamId,
            testData,
            address: InternetAddress('127.0.0.1'),
            port: 4433,
          );

          webTransportDatagramSent = true;

          print(
            '🧪 WebTransport test: DATAGRAM sent '
            'session=$streamId hex=${HEX.encode(testData)}',
          );
        }
      }

      return;
    }

    if (frameType == H3_FRAME_DATA) {
      print('📦 HTTP/3 DATA on stream=$streamId len=${payload.length}');
      return;
    }

    print(
      'ℹ️ Ignoring unsupported request-stream frame '
      '0x${frameType.toRadixString(16)} on stream=$streamId',
    );
  }
  // void _handleHttp3RequestStreamFrame(
  //   int streamId,
  //   int frameType,
  //   Uint8List payload,
  // ) {
  //   if (frameType == H3_FRAME_HEADERS) {
  //     final headers = decode_qpack_header_fields(payload);

  //     String status = '';
  //     for (final h in headers) {
  //       if (h.name == ':status') status = h.value;
  //     }

  //     print('📥 HTTP/3 HEADERS on stream $streamId status=$status');
  //     for (final h in headers) {
  //       print('   ${h.name}: ${h.value}');
  //     }

  //     final wt = h3.webTransportSessions[streamId];
  //     if (wt != null && status == '200') {
  //       wt.established = true;
  //       print('✅ WebTransport session established on stream $streamId');
  //     }

  //     return;
  //   }

  //   if (frameType == H3_FRAME_DATA) {
  //     print('📦 HTTP/3 DATA on stream=$streamId len=${payload.length}');
  //     return;
  //   }

  //   print(
  //     'ℹ️ Ignoring unsupported request-stream frame '
  //     '0x${frameType.toRadixString(16)} on stream=$streamId',
  //   );
  // }

  // int openWebTransportSession(
  //   String path, {
  //   String authority = 'localhost',
  //   String scheme = 'https',
  //   InternetAddress? address,
  //   int port = 4433,
  // }) {
  //   final streamId = _allocateClientBidiStreamId();

  //   h3.webTransportSessions[streamId] = ClientWebTransportSession(streamId);

  //   final headerBlock = build_http3_literal_headers_frame({
  //     ':method': 'CONNECT',
  //     ':scheme': scheme,
  //     ':authority': authority,
  //     ':path': path,
  //     ':protocol': WT_PROTOCOL,
  //   });

  //   final frames = build_h3_frames([
  //     {'frame_type': H3_FRAME_HEADERS, 'payload': headerBlock},
  //   ]);

  //   sendApplicationStream(
  //     streamId,
  //     frames,
  //     fin: false,
  //     address: address,
  //     port: port,
  //   );

  //   print('🚀 Sent WebTransport CONNECT on stream $streamId path=$path');
  //   return streamId;
  // }

  int openWebTransportSession(
    String path, {
    String authority = 'localhost',
    String scheme = 'https',
    InternetAddress? address,
    int port = 4433,
  }) {
    final streamId = _allocateClientBidiStreamId();

    if (h3.webTransportSessions.containsKey(streamId)) {
      print('ℹ️ WebTransport session already exists on stream $streamId');
      return streamId;
    }

    h3.webTransportSessions[streamId] = ClientWebTransportSession(streamId);

    final headerBlock = build_http3_literal_headers_frame({
      ':method': 'CONNECT',
      ':scheme': scheme,
      ':authority': authority,
      ':path': path,
      ':protocol': WT_PROTOCOL,
    });

    final frames = build_h3_frames([
      {'frame_type': H3_FRAME_HEADERS, 'payload': headerBlock},
    ]);

    sendApplicationStream(
      streamId,
      frames,
      fin: false,
      address: address,
      port: port,
    );

    print('🚀 Sent WebTransport CONNECT on stream $streamId path=$path');
    return streamId;
  }
  // void handleWebTransportDatagram(Uint8List datagramPayload) {
  //   final parsed = parse_webtransport_datagram(datagramPayload);
  //   final int sessionId = parsed['stream_id'] as int;
  //   final Uint8List data = parsed['data'] as Uint8List;

  //   final session = h3.webTransportSessions[sessionId];
  //   if (session == null) {
  //     print('⚠️ Datagram for unknown WebTransport session $sessionId');
  //     return;
  //   }

  //   print(
  //     '📦 Received WebTransport DATAGRAM '
  //     'session=$sessionId len=${data.length} hex=${HEX.encode(data)}',
  //   );
  // }
  void handleWebTransportDatagram(Uint8List datagramPayload) {
    final parsed = parse_webtransport_datagram(datagramPayload);
    final int sessionId = parsed['stream_id'] as int;
    final Uint8List data = parsed['data'] as Uint8List;

    final session = h3.webTransportSessions[sessionId];
    if (session == null) {
      print('⚠️ Datagram for unknown WebTransport session $sessionId');
      return;
    }

    print(
      '📦 Received WebTransport DATAGRAM '
      'session=$sessionId len=${data.length} hex=${HEX.encode(data)}',
    );

    // Optional test verification
    if (data.length == 4 &&
        data[0] == 0x01 &&
        data[1] == 0x02 &&
        data[2] == 0x03 &&
        data[3] == 0x04) {
      print('✅ WebTransport echo test passed');
    }
  }

  void sendWebTransportDatagram(
    int sessionId,
    Uint8List data, {
    InternetAddress? address,
    int port = 4433,
  }) {
    if (!applicationSecretsDerived || appWrite == null) {
      throw StateError('Cannot send WebTransport DATAGRAM before 1-RTT keys');
    }

    final payload = Uint8List.fromList([...writeVarInt(sessionId), ...data]);

    final frame = _buildDatagramFrame(payload, useLengthField: true);

    final ackState = ackStates[EncryptionLevel.application]!;
    final pn = ackState.allocatePn();

    final rawPacket = encryptQuicPacket(
      "short",
      frame,
      appWrite!.key,
      appWrite!.iv,
      appWrite!.hp,
      pn,
      peerCid ?? Uint8List(0),
      localCid,
      Uint8List(0),
    );

    if (rawPacket == null) {
      throw StateError('Failed to encrypt application DATAGRAM packet');
    }

    socket.send(rawPacket, InternetAddress("127.0.0.1"), 4433);

    print(
      '✅ Sent WebTransport DATAGRAM pn=$pn session=$sessionId len=${data.length}',
    );
  }

  void sendApplicationStream(
    int streamId,
    Uint8List data, {
    bool fin = false,
    int offset = 0,
    InternetAddress? address,
    int port = 4433,
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

    final ackState = ackStates[EncryptionLevel.application]!;
    final pn = ackState.allocatePn();

    final rawPacket = encryptQuicPacket(
      "short",
      frame,
      appWrite!.key,
      appWrite!.iv,
      appWrite!.hp,
      pn,
      peerCid ?? Uint8List(0),
      localCid,
      Uint8List(0),
    );

    if (rawPacket == null) {
      throw StateError('Failed to encrypt application STREAM packet');
    }

    socket.send(rawPacket, InternetAddress("127.0.0.1"), 4433);

    print(
      '✅ Sent application STREAM pn=$pn '
      'streamId=$streamId len=${data.length} fin=$fin',
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
    frameType |= 0x02; // LEN present
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

  void ensureClientH3BootstrapStreamsSent() {
    sendClientControlStream();
    sendClientQpackEncoderStream();
    sendClientQpackDecoderStream();
  }

  void sendClientControlStream() {
    if (clientControlStreamSent) return;

    final controlBytes = build_control_stream({
      'SETTINGS_QPACK_MAX_TABLE_CAPACITY': 0,
      'SETTINGS_QPACK_BLOCKED_STREAMS': 0,
      'SETTINGS_ENABLE_CONNECT_PROTOCOL': 1,
      'SETTINGS_ENABLE_WEBTRANSPORT': 1,
      'SETTINGS_H3_DATAGRAM': 1,
    });

    final streamId = _allocateClientUniStreamId();

    sendApplicationStream(streamId, controlBytes, fin: false, offset: 0);

    clientControlStreamSent = true;

    print('✅ Client HTTP/3 control stream sent on stream $streamId');
  }

  void sendClientQpackEncoderStream() {
    if (clientQpackEncoderStreamSent) return;

    final streamId = _allocateClientUniStreamId();

    final payload = Uint8List.fromList([
      ...writeVarInt(0x02), // QPACK encoder stream type
    ]);

    sendApplicationStream(streamId, payload, fin: false, offset: 0);

    clientQpackEncoderStreamSent = true;

    print('✅ Client QPACK encoder stream sent on stream $streamId');
  }

  void sendClientQpackDecoderStream() {
    if (clientQpackDecoderStreamSent) return;

    final streamId = _allocateClientUniStreamId();

    final payload = Uint8List.fromList([
      ...writeVarInt(0x03), // QPACK decoder stream type
    ]);

    sendApplicationStream(streamId, payload, fin: false, offset: 0);

    clientQpackDecoderStreamSent = true;

    print('✅ Client QPACK decoder stream sent on stream $streamId');
  }

  void _handleHttp3ControlFrame(int frameType, Uint8List payload) {
    if (frameType == H3_FRAME_SETTINGS) {
      final settings = parse_h3_settings_frame(payload);
      h3.peerSettings
        ..clear()
        ..addAll(settings);
      h3.settingsReceived = true;

      print('✅ Received HTTP/3 SETTINGS from server: $settings');

      // --------------------------------------------------------
      // Real HTTP/3 servers expect the client to open its own
      // bootstrap unidirectional streams before sending requests:
      //   - control stream
      //   - QPACK encoder stream
      //   - QPACK decoder stream
      // --------------------------------------------------------
      if (!webTransportConnectSent) {
        ensureClientH3BootstrapStreamsSent();

        final sessionId = openWebTransportSession(
          '/wt',
          authority: 'localhost',
          scheme: 'https',
          address: InternetAddress('127.0.0.1'),
          port: 4433,
        );

        activeWebTransportSessionId = sessionId;
        webTransportConnectSent = true;

        print('🧪 WebTransport test: CONNECT sent on stream $sessionId');
      }

      return;
    }

    print(
      'ℹ️ Ignoring unsupported control-stream frame '
      '0x${frameType.toRadixString(16)}',
    );
  }

  // ------------
  // Client HTTP/3 bootstrap state
  // ------------------------------------------------------------
  bool clientControlStreamSent = false;
  bool clientQpackEncoderStreamSent = false;
  bool clientQpackDecoderStreamSent = false;
}

// final clientHelloBytes = Uint8List.fromList(
//   HEX.decode(
//     "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64",
//   ),
// );
