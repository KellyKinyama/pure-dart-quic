// HTTP/3 + WEBTRANSPORT INTEGRATION INTO *YOUR* QuicServerSession
// ============================================================
// This page shows the *missing* variables and methods you need to add to
// your existing QuicServerSession so that the updated _parsePayload()
// can correctly call into HTTP/3 / WebTransport.
//
// Assumptions:
// - Your corrected h3_qpack.dart is available.
// - Your _parsePayload() already calls:
//     handleHttp3StreamChunk(...)
//     handleWebTransportDatagram(...)
// - Your 1-RTT keys are installed in appWrite/appRead.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../../packet/quic_packet.dart';
import '../../utils.dart';
import '../constants.dart';
// import '../h31.dart';
// import 'h3_qpack.dart';
// import '../../../utils.dart';
// import 'constants.dart';
import 'h3.dart';

// ------------------------------------------------------------
// HTTP/3 + WebTransport constants
// ------------------------------------------------------------

const int H3_FRAME_DATA = 0x00;
const int H3_FRAME_HEADERS = 0x01;
const int H3_FRAME_SETTINGS = 0x04;

const int H3_STREAM_TYPE_CONTROL = 0x00;
const String WT_PROTOCOL = 'webtransport';

// ------------------------------------------------------------
// Per-connection HTTP/3 / WebTransport state
// ------------------------------------------------------------

class Http3State {
  bool controlStreamSent = false;

  // QUIC stream reassembly for HTTP/3 frames
  final Map<int, Map<int, Uint8List>> streamChunks =
      <int, Map<int, Uint8List>>{};
  final Map<int, int> streamReadOffsets = <int, int>{};

  // WebTransport sessions keyed by CONNECT stream id
  final Map<int, WebTransportSession> webTransportSessions =
      <int, WebTransportSession>{};
}

class WebTransportSession {
  final int connectStreamId;
  final Set<int> streams = <int>{};

  WebTransportSession(this.connectStreamId);
}

// ------------------------------------------------------------
// ADD THESE FIELDS INSIDE QuicServerSession
// ------------------------------------------------------------
//
//   final Http3State h3 = Http3State();
//   int nextServerBidiStreamId = 1; // server-initiated bidirectional
//   int nextServerUniStreamId = 3;  // server-initiated unidirectional
//
// ------------------------------------------------------------
// ALSO ADD THIS IMPORT TO YOUR SERVER FILE
// ------------------------------------------------------------
//
//   import 'h3_qpack.dart';
//
// ------------------------------------------------------------
// CALL THIS AFTER _deriveApplicationSecrets() IN _maybeHandleClientFinished()
// ------------------------------------------------------------
//
//   sendHttp3ControlStream();
//

mixin Http3WebTransportMixin {
  // The host class must provide these members.
  QuicKeys? get appWrite;
  bool get applicationSecretsDerived;
  late Uint8List peerScid;
  late Uint8List localCid;
  late RawDatagramSocket socket;
  late InternetAddress peerAddress;
  late int peerPort;

  int _allocateSendPn(EncryptionLevel level);

  // Added fields expected on the host class:
  Http3State get h3;
  int get nextServerUniStreamId;
  set nextServerUniStreamId(int v);

  // ----------------------------------------------------------
  // 1) Send HTTP/3 control stream once 1-RTT is ready
  // ----------------------------------------------------------

  void sendHttp3ControlStream() {
    if (h3.controlStreamSent) return;
    if (!applicationSecretsDerived || appWrite == null) {
      throw StateError('Cannot send HTTP/3 control stream before 1-RTT keys');
    }

    final settingsPayload = build_settings_frame({
      'SETTINGS_QPACK_MAX_TABLE_CAPACITY': 0,
      'SETTINGS_QPACK_BLOCKED_STREAMS': 0,
      'SETTINGS_ENABLE_CONNECT_PROTOCOL': 1,
      'SETTINGS_ENABLE_WEBTRANSPORT': 1,
      'SETTINGS_H3_DATAGRAM': 1,
    });

    final controlStreamBytes = Uint8List.fromList([
      ...writeVarInt(H3_STREAM_TYPE_CONTROL),
      ...writeVarInt(H3_FRAME_SETTINGS),
      ...writeVarInt(settingsPayload.length),
      ...settingsPayload,
    ]);

    sendApplicationUnidirectionalStream(controlStreamBytes, fin: false);
    h3.controlStreamSent = true;

    print('✅ HTTP/3 control stream sent');
  }

  // ----------------------------------------------------------
  // 2) Reassemble HTTP/3 bytes by QUIC stream offset
  // ----------------------------------------------------------

  void handleHttp3StreamChunk(
    int streamId,
    int streamOffset,
    Uint8List streamData, {
    required bool fin,
  }) {
    final chunks = h3.streamChunks.putIfAbsent(
      streamId,
      () => <int, Uint8List>{},
    );
    final readOffset = h3.streamReadOffsets[streamId] ?? 0;

    // IMPORTANT: store by QUIC STREAM offset, not arrival order.
    chunks[streamOffset] = streamData;

    final extracted = extract_h3_frames_from_chunks(chunks, readOffset);
    h3.streamReadOffsets[streamId] = extracted['new_from_offset'] as int;

    for (final frame in extracted['frames']) {
      final int type = frame['frame_type'] as int;
      final Uint8List payload = frame['payload'] as Uint8List;

      if (type == H3_FRAME_HEADERS) {
        _handleHttp3HeadersFrame(streamId, payload);
        continue;
      }

      if (type == H3_FRAME_DATA) {
        print('📦 HTTP/3 DATA on stream=$streamId len=${payload.length}');
        // Add request body handling here later if needed.
        continue;
      }

      if (type == H3_FRAME_SETTINGS) {
        print('ℹ️ Ignoring unexpected SETTINGS on stream=$streamId');
        continue;
      }

      print(
        'ℹ️ Ignoring unsupported HTTP/3 frame type '
        '0x${type.toRadixString(16)} on stream=$streamId',
      );
    }

    if (fin) {
      print('✅ QUIC stream $streamId FIN received');
    }
  }

  // ----------------------------------------------------------
  // 3) Parse HTTP/3 HEADERS: normal HTTP or WebTransport CONNECT
  // ----------------------------------------------------------

  void _handleHttp3HeadersFrame(int streamId, Uint8List headerBlock) {
    final headers = decode_qpack_header_fields(headerBlock);

    String method = '';
    String path = '';
    String protocol = '';

    for (final h in headers) {
      if (h.name == ':method') method = h.value;
      if (h.name == ':path') path = h.value;
      if (h.name == ':protocol') protocol = h.value;
    }

    // WebTransport CONNECT
    if (method == 'CONNECT' && protocol == WT_PROTOCOL) {
      _acceptWebTransportSession(streamId);
      return;
    }

    // Normal HTTP/3 request
    print('📥 HTTP/3 request on stream $streamId: $method $path');

    final body = Uint8List.fromList(utf8.encode('hello from http/3'));

    final responseHeaderBlock = build_http3_literal_headers_frame({
      ':status': '200',
      'content-type': 'text/plain; charset=utf-8',
      'content-length': body.length,
    });

    final responseFrames = build_h3_frames([
      {'frame_type': H3_FRAME_HEADERS, 'payload': responseHeaderBlock},
      {'frame_type': H3_FRAME_DATA, 'payload': body},
    ]);

    sendApplicationStream(streamId, responseFrames, fin: true);
  }

  // ----------------------------------------------------------
  // 4) Accept WebTransport CONNECT stream
  // ----------------------------------------------------------

  void _acceptWebTransportSession(int streamId) {
    print('✅ WebTransport session accepted on stream $streamId');

    h3.webTransportSessions[streamId] = WebTransportSession(streamId);

    final responseHeaderBlock = build_http3_literal_headers_frame({
      ':status': '200',
      'sec-webtransport-http3-draft': 'draft02',
    });

    final frames = build_h3_frames([
      {'frame_type': H3_FRAME_HEADERS, 'payload': responseHeaderBlock},
    ]);

    // IMPORTANT: keep CONNECT stream open.
    sendApplicationStream(streamId, frames, fin: false);
  }

  // ----------------------------------------------------------
  // 5) Handle WebTransport datagrams (payload = sessionId || appData)
  // ----------------------------------------------------------

  void handleWebTransportDatagram(Uint8List datagramPayload) {
    final parsed = parse_webtransport_datagram(datagramPayload);
    final int sessionId = parsed['stream_id'] as int;
    final Uint8List data = parsed['data'] as Uint8List;

    final session = h3.webTransportSessions[sessionId];
    if (session == null) {
      print('⚠️ Datagram for unknown WebTransport session $sessionId');
      return;
    }

    print('📦 WebTransport datagram session=$sessionId len=${data.length}');

    // Echo example.
    sendWebTransportDatagram(sessionId, data);
  }

  // ----------------------------------------------------------
  // 6) Send application data on an existing QUIC stream id
  // ----------------------------------------------------------

  void sendApplicationStream(
    int streamId,
    Uint8List data, {
    bool fin = false,
    int offset = 0,
  }) {
    if (!applicationSecretsDerived || appWrite == null) {
      throw StateError('Cannot send application stream before 1-RTT keys');
    }

    final frame = _buildStreamFrame(
      streamId: streamId,
      data: data,
      offset: offset,
      fin: fin,
    );

    final pn = _allocateSendPn(EncryptionLevel.application);

    final raw = encryptQuicPacket(
      'short',
      frame,
      appWrite!.key,
      appWrite!.iv,
      appWrite!.hp,
      pn,
      peerScid,
      localCid,
      Uint8List(0),
    );

    if (raw == null) {
      throw StateError('Failed to encrypt application STREAM packet');
    }

    socket.send(raw, peerAddress, peerPort);

    print(
      '✅ Sent application STREAM pn=$pn streamId=$streamId '
      'len=${data.length} fin=$fin',
    );
  }

  // ----------------------------------------------------------
  // 7) Send a new server-initiated unidirectional stream
  // ----------------------------------------------------------

  int _allocateServerUniStreamId() {
    final id = nextServerUniStreamId;
    nextServerUniStreamId += 4;
    return id;
  }

  void sendApplicationUnidirectionalStream(Uint8List data, {bool fin = false}) {
    final streamId = _allocateServerUniStreamId();
    sendApplicationStream(streamId, data, fin: fin, offset: 0);
  }

  // ----------------------------------------------------------
  // 8) Send a WebTransport datagram
  // ----------------------------------------------------------

  void sendWebTransportDatagram(int sessionId, Uint8List data) {
    if (!applicationSecretsDerived || appWrite == null) {
      throw StateError('Cannot send WebTransport DATAGRAM before 1-RTT keys');
    }

    final payload = Uint8List.fromList([...writeVarInt(sessionId), ...data]);

    final frame = _buildDatagramFrame(payload, useLengthField: true);

    final pn = _allocateSendPn(EncryptionLevel.application);

    final raw = encryptQuicPacket(
      'short',
      frame,
      appWrite!.key,
      appWrite!.iv,
      appWrite!.hp,
      pn,
      peerScid,
      localCid,
      Uint8List(0),
    );

    if (raw == null) {
      throw StateError('Failed to encrypt DATAGRAM packet');
    }

    socket.send(raw, peerAddress, peerPort);

    print(
      '✅ Sent WebTransport DATAGRAM pn=$pn session=$sessionId len=${data.length}',
    );
  }

  // ----------------------------------------------------------
  // 9) Build a QUIC STREAM frame
  // ----------------------------------------------------------

  Uint8List _buildStreamFrame({
    required int streamId,
    required Uint8List data,
    int offset = 0,
    bool fin = false,
  }) {
    int frameType = 0x08;
    if (fin) frameType |= 0x01;
    frameType |= 0x02; // always include LEN
    if (offset != 0) frameType |= 0x04;

    return Uint8List.fromList([
      ...writeVarInt(frameType),
      ...writeVarInt(streamId),
      if (offset != 0) ...writeVarInt(offset),
      ...writeVarInt(data.length),
      ...data,
    ]);
  }

  // ----------------------------------------------------------
  // 10) Build a QUIC DATAGRAM frame
  // ----------------------------------------------------------

  Uint8List _buildDatagramFrame(
    Uint8List payload, {
    bool useLengthField = true,
  }) {
    if (useLengthField) {
      return Uint8List.fromList([
        ...writeVarInt(0x31),
        ...writeVarInt(payload.length),
        ...payload,
      ]);
    }

    return Uint8List.fromList([...writeVarInt(0x30), ...payload]);
  }
}

// ------------------------------------------------------------
// HOW TO WIRE THIS INTO QuicServerSession
// ------------------------------------------------------------
// 1) Make QuicServerSession use the mixin:
//
//    class QuicServerSession with Http3WebTransportMixin {
//      ...
//    }
//
// 2) Add the missing fields inside QuicServerSession:
//
//    final Http3State h3 = Http3State();
//    int nextServerBidiStreamId = 1;
//    int nextServerUniStreamId = 3;
//
// 3) Add this import to your server file:
//
//    import 'h3_qpack.dart';
//
// 4) In _maybeHandleClientFinished(), after _deriveApplicationSecrets():
//
//    sendHttp3ControlStream();
//
// 5) Your _parsePayload() is already calling:
//
//    handleHttp3StreamChunk(...)
//    handleWebTransportDatagram(...)
//
// That completes the HTTP/3 + WebTransport wiring.
