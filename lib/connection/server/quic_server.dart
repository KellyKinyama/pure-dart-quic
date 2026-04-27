import 'dart:io';

class QuicServer {
 RawDatagramSocket socket;
  QuicServerSession? session;

  void listen();
}
