import 'quic_key_schedule.dart';

class QuicServerSession {
 final QuicKeySchedule keys;  
 final QuicConnectionContext connection;
  final H3ServerContext h3;

  void _deriveInitialKeysFromFirstPacket(Uint8List pkt) {
  final cids = _extractLongHeaderCids(pkt);

  clientOrigDcid = cids.$1;
  peerScid = cids.$2;

  keys.deriveInitial(clientDcid: clientOrigDcid);

  initialRead = keys.initialRead;
  initialWrite = keys.initialWrite;

  initialKeysReady = true;

  print('✅ Server Initial keys ready');
}
void _deriveHandshakeKeys(ClientHello clientHello) {
  serverHelloMsg = keys.deriveHandshake(
    clientHello: clientHello,
    clientHelloMsg: clientHelloMsg!,
    serverRandom: serverRandom,
    serverPublicKey: keyPair.publicKeyBytes,
  );

  handshakeRead = keys.handshakeRead;
  handshakeWrite = keys.handshakeWrite;

  print('✅ Server handshake keys ready');
}
void _deriveApplicationSecrets() {
  keys.deriveApplication(transcriptThroughServerFinishedBytes!);

  appRead = keys.appRead;
  appWrite = keys.appWrite;

  applicationSecretsDerived = true;
  encryptionLevel = EncryptionLevel.application;

  print('✅ Server 1‑RTT keys installed');
}

  void handleDatagram(Uint8List packet);
}
  final QuicPacketHandler packets;
