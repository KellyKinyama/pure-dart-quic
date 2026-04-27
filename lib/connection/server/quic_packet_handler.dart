class QuicPacketHandler {
  final QuicConnectionContext ctx;
  final QuicKeySchedule keys;

  QuicDecryptedPacket decrypt(Uint8List packet);
  Uint8List encrypt(...);
}
