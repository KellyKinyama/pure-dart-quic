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
import 'recovery/recovery.dart';

class _QueuedStreamSend {
  final int streamId;
  final Uint8List data;
  final bool fin;
  final int offset;
  const _QueuedStreamSend(this.streamId, this.data, this.fin, this.offset);
}

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

  /// Wall-clock of the most recent inbound activity (datagram or ACK).
  /// Used by [QuicServerEndpoint] for idle-timeout eviction.
  DateTime lastActivity = DateTime.now();

  // ---------------- RFC 9002 loss recovery ----------------
  final RttEstimator _rtt = RttEstimator();
  final NewRenoController _cc = NewRenoController();
  late final LossRecovery _recovery;
  late final PtoTimer _pto;
  StreamFrameRecord? _pendingStreamFrame;
  final List<_QueuedStreamSend> _sendQueue = <_QueuedStreamSend>[];

  LossRecovery get lossRecovery => _recovery;
  NewRenoController get congestionController => _cc;
  RttEstimator get rttEstimator => _rtt;

  ServerQuicConnection({
    required this.engineSession,
    required this.udp,
    String alpn = 'h3',
    bool externalAppProtocol = true,
  }) : _alpn = alpn {
    engineSession.externalAppProtocol = externalAppProtocol;

    _recovery = LossRecovery(rtt: _rtt, cc: _cc);
    _pto = PtoTimer(_recovery);
    _recovery.onPacketsLost = _retransmitLost;
    _recovery.onPtoProbe = _sendProbe;

    engineSession.onApplicationPacketSent = (pn, size, ackEliciting) {
      final frames = _pendingStreamFrame == null
          ? const <RetransmittableFrame>[]
          : <RetransmittableFrame>[_pendingStreamFrame!];
      _pendingStreamFrame = null;
      _recovery.onPacketSent(
        SentPacket(
          pn: pn,
          sentTime: DateTime.now(),
          sizeInBytes: size,
          ackEliciting: ackEliciting,
          inFlight: ackEliciting,
          frames: frames,
        ),
      );
      _pto.rearm();
    };

    engineSession.onApplicationAckParsed = (largest, delayUs, ranges) {
      lastActivity = DateTime.now();
      _recovery.onAckReceived(
        largestAcked: largest,
        ackedRanges: ranges,
        ackDelayUs: delayUs,
        isHandshakeConfirmed: true,
      );
      _pto.rearm();
      _drainSendQueue();
    };

    engineSession.onConnectionClose = (errorCode, reason, isApp) {
      if (!_closed.isCompleted) _closed.complete();
    };

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
    lastActivity = DateTime.now();
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
    final estSize = data.length + 50;
    if (!_cc.canSend(estSize)) {
      _sendQueue.add(_QueuedStreamSend(streamId, data, fin, offset));
      return;
    }
    _pendingStreamFrame = StreamFrameRecord(
      streamId: streamId,
      offset: offset,
      data: data,
      fin: fin,
    );
    engineSession.sendApplicationStream(
      streamId,
      data,
      fin: fin,
      offset: offset,
    );
    _pendingStreamFrame = null;
  }

  void _drainSendQueue() {
    while (_sendQueue.isNotEmpty) {
      final next = _sendQueue.first;
      if (!_cc.canSend(next.data.length + 50)) break;
      _sendQueue.removeAt(0);
      _sendOnEngine(
        next.streamId,
        next.data,
        fin: next.fin,
        offset: next.offset,
      );
    }
  }

  void _retransmitLost(List<SentPacket> lost) {
    for (final p in lost) {
      for (final f in p.frames) {
        if (f is StreamFrameRecord) {
          _sendOnEngine(f.streamId, f.data, fin: f.fin, offset: f.offset);
        }
      }
    }
  }

  void _sendProbe() {
    // PTO probe: server has sendQuicPing(); fall back to retransmitting
    // the oldest in-flight stream frame if we have one.
    for (final p in _recovery.inFlightPackets) {
      for (final f in p.frames) {
        if (f is StreamFrameRecord) {
          _sendOnEngine(f.streamId, f.data, fin: f.fin, offset: f.offset);
          return;
        }
      }
    }
    engineSession.sendQuicPing();
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
    _pendingStreamFrame = null;
    engineSession.sendDatagramFrame(data);
  }

  @override
  Future<void> close({int errorCode = 0, String? reason}) async {
    _readyPoller?.cancel();
    _pto.cancel();
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
