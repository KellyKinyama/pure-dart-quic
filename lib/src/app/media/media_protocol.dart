// Media-over-QUIC (MoQ) — minimal demo module inspired by
// draft-ietf-moq-transport. NOT wire-compatible with the IETF draft;
// this implements just enough to illustrate the typical layering on
// top of `QuicConnection`:
//
//   * One bidirectional control stream (client opens it).
//   * Length-prefixed control messages with a varint type:
//        SETUP    (0x01)  client -> server  body = utf8(role)
//        SETUP_OK (0x02)  server -> client  body = ""
//        SUBSCRIBE(0x03)  client -> server  body = utf8(track)
//        ANNOUNCE (0x04)  server -> client  body = utf8(track)
//   * Media samples are sent as QUIC DATAGRAMs (RFC 9221) with a
//     small header: varint(track_id) || varint(group_id) ||
//     varint(object_id) || payload.
//
// The same stream / datagram primitives that power HTTP/3 +
// WebTransport drive this module; the only difference is the
// application-level framing.
//
// ALPN: `moq-00` (provisional in this repo, not the IETF value).

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../../../utils.dart';
import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String moqAlpn = 'moq-00';

const int moqCtrlSetup = 0x01;
const int moqCtrlSetupOk = 0x02;
const int moqCtrlSubscribe = 0x03;
const int moqCtrlAnnounce = 0x04;

class MoqObject {
  final int trackId;
  final int groupId;
  final int objectId;
  final Uint8List payload;
  const MoqObject({
    required this.trackId,
    required this.groupId,
    required this.objectId,
    required this.payload,
  });

  @override
  String toString() =>
      'MoqObject(track=$trackId group=$groupId obj=$objectId '
      'len=${payload.length})';
}

/// Encode a control message (varint type || varint len || body).
Uint8List encodeMoqControl(int type, Uint8List body) {
  final t = writeVarInt(type);
  final l = writeVarInt(body.length);
  final out = Uint8List(t.length + l.length + body.length);
  out.setRange(0, t.length, t);
  out.setRange(t.length, t.length + l.length, l);
  out.setRange(t.length + l.length, out.length, body);
  return out;
}

/// Encode a media object DATAGRAM payload.
Uint8List encodeMoqObjectDatagram(MoqObject obj) {
  final t = writeVarInt(obj.trackId);
  final g = writeVarInt(obj.groupId);
  final o = writeVarInt(obj.objectId);
  final out = Uint8List(t.length + g.length + o.length + obj.payload.length);
  var off = 0;
  out.setRange(off, off += t.length, t);
  out.setRange(off, off += g.length, g);
  out.setRange(off, off += o.length, o);
  out.setRange(off, off + obj.payload.length, obj.payload);
  return out;
}

MoqObject? decodeMoqObjectDatagram(Uint8List data) {
  var off = 0;
  final t = readVarInt(data, off);
  if (t == null) return null;
  off += t.byteLength;
  final g = readVarInt(data, off);
  if (g == null) return null;
  off += g.byteLength;
  final o = readVarInt(data, off);
  if (o == null) return null;
  off += o.byteLength;
  return MoqObject(
    trackId: t.value,
    groupId: g.value,
    objectId: o.value,
    payload: Uint8List.sublistView(data, off),
  );
}

class MoqCtrlMsg {
  final int type;
  final Uint8List body;
  const MoqCtrlMsg(this.type, this.body);
}

abstract class MediaOverQuicBase implements ApplicationProtocol {
  @override
  final String alpn = moqAlpn;
  final QuicConnection conn;

  QuicStream? _ctrl;
  final BytesBuilder _ctrlBuf = BytesBuilder();

  StreamSubscription<QuicStream>? _streamSub;
  StreamSubscription<Uint8List>? _datagramSub;
  StreamSubscription<Uint8List>? _ctrlSub;

  final StreamController<MoqObject> _objectsCtrl =
      StreamController<MoqObject>.broadcast();

  /// Inbound media objects (DATAGRAM-delivered).
  Stream<MoqObject> get objects => _objectsCtrl.stream;

  MediaOverQuicBase(this.conn);

  @override
  Future<void> start() async {
    _streamSub = conn.incomingStreams.listen(_onPeerStream);
    _datagramSub = conn.datagrams.listen(_onDatagram);
    await onStarted();
  }

  Future<void> onStarted() async {}

  @override
  Future<void> stop() async {
    await _streamSub?.cancel();
    await _datagramSub?.cancel();
    await _ctrlSub?.cancel();
    await _objectsCtrl.close();
  }

  void _onPeerStream(QuicStream s) {
    final isUni = (s.id & 0x02) != 0;
    if (isUni) return;
    if (_ctrl != null) return;
    _ctrl = s;
    _ctrlSub = s.incoming.listen(_onCtrlChunk);
    print('✅ [moq] bound control stream id=${s.id}');
    onCtrlBound();
  }

  void onCtrlBound() {}

  void _onCtrlChunk(Uint8List chunk) {
    _ctrlBuf.add(chunk);
    while (true) {
      final view = _ctrlBuf.toBytes();
      if (view.isEmpty) return;
      final t = readVarInt(view, 0);
      if (t == null) return;
      final l = readVarInt(view, t.byteLength);
      if (l == null) return;
      final headerLen = t.byteLength + l.byteLength;
      if (view.length < headerLen + l.value) return;
      final body = view.sublist(headerLen, headerLen + l.value);
      onCtrlMessage(MoqCtrlMsg(t.value, body));
      final tail = view.sublist(headerLen + l.value);
      _ctrlBuf
        ..clear()
        ..add(tail);
    }
  }

  void onCtrlMessage(MoqCtrlMsg msg) {}

  void sendCtrl(int type, Uint8List body) {
    final s = _ctrl;
    if (s == null) {
      throw StateError('[moq] control stream not bound');
    }
    s.write(encodeMoqControl(type, body));
  }

  /// Publish a media object as a QUIC DATAGRAM.
  void publish(MoqObject obj) {
    conn.sendDatagram(encodeMoqObjectDatagram(obj));
  }

  void _onDatagram(Uint8List data) {
    final obj = decodeMoqObjectDatagram(data);
    if (obj == null) return;
    print('📦 [moq] DATAGRAM $obj');
    _objectsCtrl.add(obj);
  }
}

class MediaOverQuicServerProtocol extends MediaOverQuicBase {
  final StreamController<String> _subscribesCtrl =
      StreamController<String>.broadcast();

  /// Track names the peer (client) has subscribed to.
  Stream<String> get subscribes => _subscribesCtrl.stream;

  MediaOverQuicServerProtocol(super.conn);

  @override
  void onCtrlMessage(MoqCtrlMsg msg) {
    switch (msg.type) {
      case moqCtrlSetup:
        final role = utf8.decode(msg.body);
        print('✅ [moq] SETUP role=$role');
        sendCtrl(moqCtrlSetupOk, Uint8List(0));
        break;
      case moqCtrlSubscribe:
        final track = utf8.decode(msg.body);
        print('✅ [moq] SUBSCRIBE track=$track');
        _subscribesCtrl.add(track);
        // Acknowledge with an ANNOUNCE for the same track name.
        sendCtrl(moqCtrlAnnounce, Uint8List.fromList(utf8.encode(track)));
        break;
      default:
        print(
          'ℹ️ [moq] server ignored ctrl type=0x'
          '${msg.type.toRadixString(16)}',
        );
    }
  }

  @override
  Future<void> stop() async {
    await _subscribesCtrl.close();
    await super.stop();
  }
}

class MediaOverQuicClientProtocol extends MediaOverQuicBase {
  String role;
  final Completer<void> _setupOk = Completer<void>();
  final StreamController<String> _announcesCtrl =
      StreamController<String>.broadcast();

  /// Track names announced by the server.
  Stream<String> get announces => _announcesCtrl.stream;

  /// Completes when the server replies SETUP_OK.
  Future<void> get setupCompleted => _setupOk.future;

  MediaOverQuicClientProtocol(super.conn, {this.role = 'subscriber'});

  @override
  Future<void> onStarted() async {
    final s = await conn.openBidirectionalStream();
    _ctrl = s;
    _ctrlSub = s.incoming.listen(_onCtrlChunk);
    print('🚀 [moq] opened control stream id=${s.id}');
    sendCtrl(moqCtrlSetup, Uint8List.fromList(utf8.encode(role)));
  }

  void subscribe(String track) {
    sendCtrl(moqCtrlSubscribe, Uint8List.fromList(utf8.encode(track)));
    print('🚀 [moq] sent SUBSCRIBE track=$track');
  }

  @override
  void onCtrlMessage(MoqCtrlMsg msg) {
    switch (msg.type) {
      case moqCtrlSetupOk:
        print('✅ [moq] SETUP_OK');
        if (!_setupOk.isCompleted) _setupOk.complete();
        break;
      case moqCtrlAnnounce:
        final track = utf8.decode(msg.body);
        print('✅ [moq] ANNOUNCE track=$track');
        _announcesCtrl.add(track);
        break;
      default:
        print(
          'ℹ️ [moq] client ignored ctrl type=0x'
          '${msg.type.toRadixString(16)}',
        );
    }
  }

  @override
  Future<void> stop() async {
    await _announcesCtrl.close();
    await super.stop();
  }
}

class MediaOverQuicProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [moqAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      MediaOverQuicServerProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      MediaOverQuicClientProtocol(conn);
}
