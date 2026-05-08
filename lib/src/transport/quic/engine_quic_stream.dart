// Concrete [QuicStream] implementation that bridges the modular API
// to the existing demo engine sessions.
//
// One [EngineQuicStream] exists per QUIC stream id observed on the
// connection; it routes:
//   * Inbound bytes (engine -> StreamController -> consumer)
//   * Outbound bytes (consumer -> engine.sendApplicationStream)
//   * FIN / RESET signalling
//
// Reordering / reassembly is performed here so consumers see an
// in-order byte stream regardless of QUIC packet arrival order.

import 'dart:async';
import 'dart:typed_data';

import 'quic_connection.dart';

typedef SendStreamFn =
    void Function(int streamId, Uint8List data, {bool fin, int offset});

typedef ResetStreamFn = void Function(int streamId, int errorCode);

class EngineQuicStream implements QuicStream {
  @override
  final int id;
  final SendStreamFn _send;
  final ResetStreamFn? _reset;
  final bool _readable;
  final bool _writable;

  // Per-stream inbound queue. Non-broadcast so bytes that arrive
  // before the consumer subscribes are buffered, not dropped.
  final StreamController<Uint8List> _incoming = StreamController<Uint8List>();

  // Outbound offset bookkeeping.
  int _writeOffset = 0;
  bool _localFin = false;

  // Inbound reassembly: chunks keyed by their start offset.
  final Map<int, Uint8List> _pending = <int, Uint8List>{};
  int _readOffset = 0;
  bool _remoteFin = false;

  EngineQuicStream({
    required this.id,
    required SendStreamFn send,
    ResetStreamFn? reset,
    bool readable = true,
    bool writable = true,
  }) : _send = send,
       _reset = reset,
       _readable = readable,
       _writable = writable;

  @override
  bool get readable => _readable;

  @override
  bool get writable => _writable;

  @override
  Stream<Uint8List> get incoming => _incoming.stream;

  /// Called by the connection adapter when the engine surfaces a
  /// STREAM frame for this stream id. Performs simple offset-based
  /// reassembly so consumers always see in-order bytes.
  void deliverIncoming(int offset, Uint8List data, bool fin) {
    if (!_readable) return;

    if (offset == _readOffset) {
      _emit(data);
      _readOffset += data.length;
      _drainPending();
    } else if (offset > _readOffset) {
      _pending[offset] = data;
    } else {
      // Overlap with already-delivered prefix: trim and emit the tail.
      final skip = _readOffset - offset;
      if (skip < data.length) {
        final tail = Uint8List.sublistView(data, skip);
        _emit(tail);
        _readOffset += tail.length;
        _drainPending();
      }
    }

    if (fin) {
      _remoteFin = true;
      if (_pending.isEmpty) _incoming.close();
    }
  }

  void _drainPending() {
    while (true) {
      final next = _pending.remove(_readOffset);
      if (next == null) break;
      _emit(next);
      _readOffset += next.length;
    }
    if (_remoteFin && _pending.isEmpty && !_incoming.isClosed) {
      _incoming.close();
    }
  }

  void _emit(Uint8List data) {
    if (data.isEmpty) return;
    _incoming.add(data);
  }

  @override
  void write(Uint8List data, {bool fin = false}) {
    if (!_writable) {
      throw StateError('Stream $id is not writable');
    }
    if (_localFin) {
      throw StateError('Stream $id already closed locally');
    }
    _send(id, data, fin: fin, offset: _writeOffset);
    _writeOffset += data.length;
    if (fin) _localFin = true;
  }

  @override
  Future<void> close() async {
    if (_localFin) return;
    _send(id, Uint8List(0), fin: true, offset: _writeOffset);
    _localFin = true;
  }

  @override
  Future<void> reset({int errorCode = 0}) async {
    if (_reset != null) {
      _reset(id, errorCode);
    }
    _localFin = true;
    if (!_incoming.isClosed) await _incoming.close();
  }
}
