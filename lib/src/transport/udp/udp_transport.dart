// UDP transport abstraction.
//
// The QUIC layer sits on top of an [UdpTransport]. The default
// implementation is [DartUdpTransport] which wraps `RawDatagramSocket`,
// but tests / simulators can implement [UdpTransport] directly to inject
// loss, reordering, or run in-memory.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

/// A single UDP datagram together with its source address.
class UdpDatagram {
  final Uint8List data;
  final InternetAddress address;
  final int port;
  UdpDatagram(this.data, this.address, this.port);
}

abstract class UdpTransport {
  /// Local bound address.
  InternetAddress get address;

  /// Local bound port.
  int get port;

  /// Stream of incoming datagrams.
  Stream<UdpDatagram> get datagrams;

  /// Send a single datagram.
  void send(Uint8List data, InternetAddress address, int port);

  /// Close the transport.
  Future<void> close();
}

/// Default transport backed by `dart:io`'s [RawDatagramSocket].
class DartUdpTransport implements UdpTransport {
  final RawDatagramSocket _socket;
  final StreamController<UdpDatagram> _ctrl =
      StreamController<UdpDatagram>.broadcast();

  DartUdpTransport._(this._socket) {
    _socket.listen((ev) {
      if (ev == RawSocketEvent.read) {
        final dg = _socket.receive();
        if (dg != null) {
          _ctrl.add(UdpDatagram(dg.data, dg.address, dg.port));
        }
      }
    });
  }

  static Future<DartUdpTransport> bind(
    InternetAddress address,
    int port,
  ) async {
    final s = await RawDatagramSocket.bind(address, port);
    return DartUdpTransport._(s);
  }

  /// Escape hatch for code that still needs the underlying socket
  /// (e.g. the demo QUIC engine which writes directly to it). New
  /// code should not depend on this — program against [UdpTransport].
  RawDatagramSocket get rawSocket => _socket;

  @override
  InternetAddress get address => _socket.address;

  @override
  int get port => _socket.port;

  @override
  Stream<UdpDatagram> get datagrams => _ctrl.stream;

  @override
  void send(Uint8List data, InternetAddress address, int port) {
    _socket.send(data, address, port);
  }

  @override
  Future<void> close() async {
    _socket.close();
    await _ctrl.close();
  }
}
