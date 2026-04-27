import 'dart:typed_data';

import '../../constants.dart';
import '../../frames/quic_ack.dart';
import '../../packet/quic_packet.dart';

class QuicConnectionContext {
  // ==========================================================
  // Connection IDs
  // ==========================================================
  late Uint8List clientOrigDcid;
  late Uint8List peerScid;
  late Uint8List localCid;

  // ==========================================================
  // Encryption & state
  // ==========================================================
  EncryptionLevel encryptionLevel = EncryptionLevel.initial;

  bool initialKeysReady = false;
  bool handshakeComplete = false;
  bool applicationSecretsDerived = false;

  // ==========================================================
  // Packet number spaces
  // ==========================================================
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

  // ==========================================================
  // ACK state
  // ==========================================================
  final Map<EncryptionLevel, AckState> ackStates = {
    EncryptionLevel.initial: AckState(),
    EncryptionLevel.handshake: AckState(),
    EncryptionLevel.application: AckState(),
  };

  // ==========================================================
  // Utilities
  // ==========================================================
  int allocateSendPn(EncryptionLevel level) {
    final pn = nextSendPn[level]!;
    nextSendPn[level] = pn + 1;
    return pn;
  }
}
