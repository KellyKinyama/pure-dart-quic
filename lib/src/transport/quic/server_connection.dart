// QUIC server adapter that exposes the existing [QuicServerSession]
// engine through the modular [QuicConnection] interface.
//
// When the endpoint sets `externalAppProtocol = true`, the engine
// stops driving its own HTTP/3 / WebTransport bootstrap; this adapter
// then:
//   * forwards inbound STREAM frames to per-id [EngineQuicStream]s,
//   * forwards inbound DATAGRAM frames to [datagrams],
//   * implements [openUnidirectionalStream] / [openBidirectionalStream]
//     and [sendDatagram] backed by the engine's
//     `sendApplicationStream` / `sendDatagramFrame`.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../../../connection/server/quic_server_session.dart';
import '../../../constants.dart';
import '../udp/udp_transport.dart';
import 'engine_quic_stream.dart';
import 'quic_connection.dart';

class ServerQuicConnection implements QuicConnection {
  final QuicServerSession engineSession;
  final UdpTransport udp;
  final String _alpn;

  final Completer<void> _ready = Completer<void>();
  final Completer<void> _closed = Completer<void>();
  final StreamController<QuicStream> _incomingStreams =
      StreamController<QuicStream>.broadcast();
  final StreamController<Uint8List> _datagrams =
      StreamController<Uint8List>.broadcast();

  final Map<int, EngineQuicStream> _streams = <int, EngineQuicStream>{};
  Timer? _readyPoller;

  ServerQuicConnection({
    required this.engineSession,
    required this.udp,
    String alpn = 'h3',
    bool externalAppProtocol = true,
  }) : _alpn = alpn {
    engineSession.externalAppProtocol = externalAppProtocol;

    if (externalAppProtocol) {
      engineSession.onIncomingStreamData = _handleIncomingStreamData;
      engineSession.onIncomingDatagram = (data) => _datagrams.add(data);
      engineSession.onApplicationReady = () {
        if (!_ready.isCompleted) _ready.complete();
      };
    } else {
      _readyPoller = Timer.periodic(const Duration(milliseconds: 25), (t) {
        if (engineSession.handshakeComplete && !_ready.isCompleted) {
          _ready.complete();
          t.cancel();
          _readyPoller = null;
        }
      });
    }
  }

  /// Feed a UDP datagram into the engine (after coalesced-packet split).
  void handleDatagram(UdpDatagram dg) {
    if (engineSession.peerAddressOrNull == null) {
      engineSession.peerAddress = dg.address;
      engineSession.peerPort = dg.port;
    }
    for (final pkt in splitCoalescedPackets(dg.data)) {
      engineSession.handleDatagram(pkt);
    }
  }

  void _handleIncomingStreamData(
    int streamId,
    int offset,
    Uint8List data,
    bool fin,
  ) {
    var stream = _streams[streamId];
    if (stream == null) {
      stream = _newPeerStream(streamId);
      _streams[streamId] = stream;
      _incomingStreams.add(stream);
    }
    stream.deliverIncoming(offset, data, fin);
  }

  EngineQuicStream _newPeerStream(int streamId) {
    final isUni = (streamId & 0x02) != 0;
    return EngineQuicStream(
      id: streamId,
      send: _sendOnEngine,
      readable: true,
      writable: !isUni,
    );
  }

  void _sendOnEngine(
    int streamId,
    Uint8List data, {
    bool fin = false,
    int offset = 0,
  }) {
    engineSession.sendApplicationStream(
      streamId,
      data,
      fin: fin,
      offset: offset,
    );
  }

  @override
  String get alpn => _alpn;

  @override
  Uint8List get peerCid => engineSession.peerScid;

  @override
  Future<void> get ready => _ready.future;

  @override
  Future<void> get closed => _closed.future;

  @override
  Stream<QuicStream> get incomingStreams => _incomingStreams.stream;

  @override
  Stream<Uint8List> get datagrams => _datagrams.stream;

  @override
  Future<QuicStream> openBidirectionalStream() async {
    final id = engineSession.allocateServerBidiStreamId();
    final s = EngineQuicStream(
      id: id,
      send: _sendOnEngine,
      readable: true,
      writable: true,
    );
    _streams[id] = s;
    return s;
  }

  @override
  Future<QuicStream> openUnidirectionalStream() async {
    final id = engineSession.allocateServerUniStreamId();
    final s = EngineQuicStream(
      id: id,
      send: _sendOnEngine,
      readable: false,
      writable: true,
    );
    _streams[id] = s;
    return s;
  }

  @override
  void sendDatagram(Uint8List data) {
    engineSession.sendDatagramFrame(data);
  }

  @override
  Future<void> close({int errorCode = 0, String? reason}) async {
    _readyPoller?.cancel();
    if (!_ready.isCompleted) _ready.completeError(StateError('closed'));
    if (!_closed.isCompleted) _closed.complete();
    await _incomingStreams.close();
    await _datagrams.close();
  }
}

extension _QuicServerSessionPeer on QuicServerSession {
  InternetAddress? get peerAddressOrNull {
    try {
      return peerAddress;
    } catch (_) {
      return null;
    }
  }
}
