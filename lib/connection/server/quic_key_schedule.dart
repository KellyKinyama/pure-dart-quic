import 'dart:typed_data';
import 'package:hex/hex.dart';

import '../../cipher/hash.dart';
import '../../cipher/hkdf.dart';
import '../../cipher/x25519.dart';
import '../../constants.dart';
import '../../handshake/client_hello.dart';
import '../../handshake/server_hello.dart';
import '../../packet/quic_packet.dart';

class QuicKeySchedule {
  // === QUIC keys ===
  QuicKeys? initialRead, initialWrite;
  QuicKeys? handshakeRead, handshakeWrite;
  QuicKeys? appRead, appWrite;

  // === TLS secrets ===
  late Uint8List handshakeSecret;
  late Uint8List clientHsTrafficSecret;
  late Uint8List serverHsTrafficSecret;
  late Uint8List derivedSecret;

  Uint8List? transcriptThroughServerFinished;

  // =========================================================
  // INITIAL secrets (RFC 9001)
  // =========================================================
  void deriveInitial({required Uint8List clientDcid}) {
    final initialSalt = Uint8List.fromList(
      HEX.decode('38762cf7f55934b34d179ae6a4c80cadccbb7f0a'),
    );

    final initialSecret = hkdfExtract(clientDcid, salt: initialSalt);

    final clientSecret = hkdfExpandLabel(
      secret: initialSecret,
      label: 'client in',
      context: Uint8List(0),
      length: 32,
    );

    final serverSecret = hkdfExpandLabel(
      secret: initialSecret,
      label: 'server in',
      context: Uint8List(0),
      length: 32,
    );

    initialRead = _deriveQuicKeys(clientSecret);
    initialWrite = _deriveQuicKeys(serverSecret);
  }

  // =========================================================
  // HANDSHAKE secrets (TLS 1.3)
  // =========================================================
  Uint8List deriveHandshake({
    required ClientHello clientHello,
    required Uint8List clientHelloMsg,
    required Uint8List serverRandom,
    required Uint8List serverPublicKey,
  }) {
    final keyShare = clientHello.keyShares!.firstWhere(
      (ks) => ks.group == 0x001d,
      orElse: () => throw StateError('No X25519 key_share'),
    );

    final sharedSecret = x25519ShareSecret(
      privateKey: serverPublicKey,
      publicKey: keyShare.pub,
    );

    final serverHello = buildServerHello(
      serverRandom: serverRandom,
      publicKey: serverPublicKey,
      sessionId: Uint8List(0),
      cipherSuite: 0x1301,
      group: keyShare.group,
    );

    final helloTranscript = Uint8List.fromList([
      ...clientHelloMsg,
      ...serverHello,
    ]);

    final helloHash = createHash(helloTranscript);
    final emptyHash = createHash(Uint8List(0));

    final earlySecret = hkdfExtract(Uint8List(32), salt: Uint8List(0));

    derivedSecret = hkdfExpandLabel(
      secret: earlySecret,
      label: 'derived',
      context: emptyHash,
      length: 32,
    );

    handshakeSecret = hkdfExtract(sharedSecret, salt: derivedSecret);

    clientHsTrafficSecret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: 'c hs traffic',
      context: helloHash,
      length: 32,
    );

    serverHsTrafficSecret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: 's hs traffic',
      context: helloHash,
      length: 32,
    );

    handshakeRead = _deriveQuicKeys(clientHsTrafficSecret);
    handshakeWrite = _deriveQuicKeys(serverHsTrafficSecret);

    return serverHello;
  }

  // =========================================================
  // APPLICATION secrets (1‑RTT)
  // =========================================================
  void deriveApplication(Uint8List transcript) {
    transcriptThroughServerFinished = transcript;

    final transcriptHash = createHash(transcript);
    final emptyHash = createHash(Uint8List(0));

    final derived = hkdfExpandLabel(
      secret: handshakeSecret,
      label: 'derived',
      context: emptyHash,
      length: 32,
    );

    final masterSecret = hkdfExtract(Uint8List(32), salt: derived);

    final clientSecret = hkdfExpandLabel(
      secret: masterSecret,
      label: 'c ap traffic',
      context: transcriptHash,
      length: 32,
    );

    final serverSecret = hkdfExpandLabel(
      secret: masterSecret,
      label: 's ap traffic',
      context: transcriptHash,
      length: 32,
    );

    appRead = _deriveQuicKeys(clientSecret);
    appWrite = _deriveQuicKeys(serverSecret);
  }

  // =========================================================
  // Helpers
  // =========================================================
  QuicKeys _deriveQuicKeys(Uint8List secret) {
    return QuicKeys(
      key: hkdfExpandLabel(
        secret: secret,
        label: 'quic key',
        context: Uint8List(0),
        length: 16,
      ),
      iv: hkdfExpandLabel(
        secret: secret,
        label: 'quic iv',
        context: Uint8List(0),
        length: 12,
      ),
      hp: hkdfExpandLabel(
        secret: secret,
        label: 'quic hp',
        context: Uint8List(0),
        length: 16,
      ),
    );
  }
}
