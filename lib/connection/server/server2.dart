import 'dart:io';

import '../../constants.dart';
import 'quic_server_session.dart';

// import '../constants.dart';
// import 'constants.dart';
// import 'quic_server_session3.dart';

Future<void> main() async {
  final socket = await RawDatagramSocket.bind("127.0.0.1", 4433);

  QuicServerSession quicSession = QuicServerSession(socket: socket);

  print("server listening ip:${socket.address.address}:${socket.port}");
  bool peerSet = false;

  socket.listen((ev) {
    if (ev == RawSocketEvent.read) {
      final dg = socket.receive();
      if (dg == null) return;

      print("Data datagram received: ${dg.data.length}");

      // ✅ Create session on first packet only
      // quicSession ??= QuicServerSession(
      //   socket: socket,
      //   // peerAddress: dg.address,
      //   // peerPort: dg.port,
      //   // ✅ NO prebuilt flight injected
      // );
      if (!peerSet) {
        quicSession.peerAddress = dg.address;
        quicSession.peerPort = dg.port;
        peerSet = true;
      }

      final packetList = splitCoalescedPackets(dg.data);
      print(packetList.length);

      for (final pkt in packetList) {
        quicSession.handleDatagram(pkt);
      }
    }
  });
}
