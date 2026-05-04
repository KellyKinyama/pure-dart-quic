// HTTP/3 (RFC 9114) + WebTransport (draft-ietf-webtrans-http3) +
// HTTP/3 DATAGRAM (RFC 9297) implemented purely on top of the modular
// [QuicConnection] API.
//
// What this module does:
//
//   * Opens a server- or client-initiated HTTP/3 control unidirectional
//     stream and sends an opening SETTINGS frame, advertising
//     SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (RFC 8441) and
//     SETTINGS_ENABLE_WEBTRANSPORT=1 + SETTINGS_H3_DATAGRAM=1.
//   * Consumes peer-initiated unidirectional streams and classifies
//     them by stream-type prefix (control / QPACK encoder / QPACK
//     decoder / WebTransport uni).
//   * Consumes peer-initiated bidirectional streams as HTTP/3 request
//     streams, parses HEADERS via the QPACK static-table decoder
//     already shipped with the engine, and dispatches extended
//     CONNECT requests with `:protocol = webtransport` to a
//     [WebTransportSession] handler.
//   * Sends + receives WebTransport DATAGRAMs (RFC 9297 wire format:
//     varint session_id || payload) via the connection-level
//     [QuicConnection.sendDatagram] / [QuicConnection.datagrams].
//
// What this module deliberately does NOT do:
//
//   * QPACK dynamic-table coding. The peer SETTINGS we advertise pin
//     QPACK_MAX_TABLE_CAPACITY=0, matching the engine's behaviour.
//   * HTTP/3 priority, GOAWAY, MAX_PUSH_ID, server push.
//   * Flow control beyond what QUIC itself provides.

import 'dart:async';
import 'dart:typed_data';

import '../../../h3/h3.dart' as h3;
import '../../../utils.dart';
import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String h3Alpn = 'h3';

const int _h3StreamTypeControl = 0x00;
const int _h3StreamTypeQpackEncoder = 0x02;
const int _h3StreamTypeQpackDecoder = 0x03;
const int _wtStreamTypeUni = 0x54;

const int _h3FrameSettings = 0x04;
const int _h3FrameHeaders = 0x01;

const Map<String, int> _defaultSettings = <String, int>{
  'SETTINGS_QPACK_MAX_TABLE_CAPACITY': 0,
  'SETTINGS_QPACK_BLOCKED_STREAMS': 0,
  'SETTINGS_ENABLE_CONNECT_PROTOCOL': 1,
  'SETTINGS_ENABLE_WEBTRANSPORT': 1,
  'SETTINGS_H3_DATAGRAM': 1,
};

/// Application handle for a WebTransport session established over an
/// extended-CONNECT request stream.
class WebTransportSession {
  /// HTTP/3 request stream id on which CONNECT was issued. The stream
  /// id is also the WebTransport session id used to multiplex
  /// DATAGRAMs (RFC 9297 + draft-ietf-webtrans-http3).
  final int sessionId;
  final Http3ProtocolBase _owner;

  final StreamController<Uint8List> _datagrams = StreamController<Uint8List>();

  WebTransportSession._(this.sessionId, this._owner);

  /// Inbound WebTransport DATAGRAMs for this session.
  Stream<Uint8List> get datagrams => _datagrams.stream;

  /// Send a WebTransport DATAGRAM (RFC 9297 wire format:
  /// varint session_id || payload).
  void sendDatagram(Uint8List payload) {
    final framed = Uint8List.fromList(<int>[
      ...writeVarInt(sessionId),
      ...payload,
    ]);
    _owner.conn.sendDatagram(framed);
  }

  void _deliverDatagram(Uint8List payload) {
    _datagrams.add(payload);
  }

  Future<void> close() async {
    await _datagrams.close();
  }
}

class _PeerUniStream {
  final int streamId;
  final BytesBuilder buffer = BytesBuilder();
  int? streamType;

  _PeerUniStream(this.streamId);
}

class _PeerBidiStream {
  final int streamId;
  final Map<int, Uint8List> chunks = <int, Uint8List>{};
  int readOffset = 0;
  int incomingOffset = 0;

  _PeerBidiStream(this.streamId);
}

/// Shared HTTP/3 state machine. Concrete subclasses only differ in how
/// they bootstrap (server vs client).
abstract class Http3ProtocolBase implements ApplicationProtocol {
  @override
  final String alpn;
  final QuicConnection conn;

  final StreamController<WebTransportSession> _wtSessionsCtrl =
      StreamController<WebTransportSession>.broadcast();

  /// Fires once for each accepted WebTransport session.
  Stream<WebTransportSession> get webTransportSessions =>
      _wtSessionsCtrl.stream;

  Map<String, int> peerSettings = <String, int>{};
  bool peerSettingsReceived = false;

  // ignore: unused_field
  QuicStream? _localControlStream;

  final Map<int, _PeerUniStream> _peerUniStreams = <int, _PeerUniStream>{};
  final Map<int, _PeerBidiStream> _peerBidiStreams = <int, _PeerBidiStream>{};
  final Map<int, WebTransportSession> _wtSessions =
      <int, WebTransportSession>{};

  StreamSubscription<QuicStream>? _streamSub;
  StreamSubscription<Uint8List>? _datagramSub;

  Http3ProtocolBase(this.conn, this.alpn);

  @override
  Future<void> start() async {
    _streamSub = conn.incomingStreams.listen(_onPeerStream);
    _datagramSub = conn.datagrams.listen(_onDatagram);
    await _openLocalControlStream();
    await onStarted();
  }

  /// Subclass extension point invoked once the local control stream
  /// has been opened and SETTINGS sent.
  Future<void> onStarted() async {}

  @override
  Future<void> stop() async {
    await _streamSub?.cancel();
    await _datagramSub?.cancel();
    for (final s in _wtSessions.values) {
      await s.close();
    }
    await _wtSessionsCtrl.close();
  }

  // ---------------------------------------------------------------
  // Outbound: control stream + SETTINGS
  // ---------------------------------------------------------------

  Future<void> _openLocalControlStream() async {
    final stream = await conn.openUnidirectionalStream();
    _localControlStream = stream;
    final bytes = h3.build_control_stream(_defaultSettings);
    stream.write(bytes);
    print('✅ [h3:$alpn] sent SETTINGS on control stream ${stream.id}');
  }

  // ---------------------------------------------------------------
  // Inbound: peer streams
  // ---------------------------------------------------------------

  void _onPeerStream(QuicStream stream) {
    final id = stream.id;
    final isUni = (id & 0x02) != 0;
    if (isUni) {
      final s = _PeerUniStream(id);
      _peerUniStreams[id] = s;
      stream.incoming.listen(
        (chunk) => _onPeerUniChunk(s, chunk),
        onDone: () => _peerUniStreams.remove(id),
      );
    } else {
      final s = _PeerBidiStream(id);
      _peerBidiStreams[id] = s;
      stream.incoming.listen(
        (chunk) => _onPeerBidiChunk(stream, s, chunk),
        onDone: () => _peerBidiStreams.remove(id),
      );
    }
  }

  void _onPeerUniChunk(_PeerUniStream s, Uint8List chunk) {
    s.buffer.add(chunk);
    var view = s.buffer.toBytes();

    // Step 1: read the stream type prefix (varint) once.
    if (s.streamType == null) {
      final dynamic res = readVarInt(view, 0);
      if (res == null) return; // need more bytes
      s.streamType = res.value as int;
      final prefixLen = res.byteLength as int;
      view = Uint8List.sublistView(view, prefixLen);
      s.buffer
        ..clear()
        ..add(view);
      print(
        '✅ [h3:$alpn] peer uni stream ${s.streamId} '
        'type=0x${s.streamType!.toRadixString(16)}',
      );
    }

    switch (s.streamType) {
      case _h3StreamTypeControl:
        _consumePeerControlBytes(s);
        break;
      case _h3StreamTypeQpackEncoder:
      case _h3StreamTypeQpackDecoder:
        // QPACK dynamic-table updates accepted but ignored: we
        // advertise capacity = 0 so peers shouldn't push entries.
        s.buffer.clear();
        break;
      case _wtStreamTypeUni:
        // Opaque WebTransport unidirectional stream. Surface as a
        // raw chunk on the corresponding session if one exists.
        s.buffer.clear();
        break;
      default:
        s.buffer.clear();
    }
  }

  void _consumePeerControlBytes(_PeerUniStream s) {
    final view = s.buffer.toBytes();
    if (view.isEmpty) return;
    final chunks = <int, Uint8List>{0: view};
    final extracted = h3.extract_h3_frames_from_chunks(chunks, 0);
    final frames = extracted['frames'] as List<dynamic>;
    final consumed = extracted['new_from_offset'] as int;

    if (consumed > 0) {
      final remaining = view.sublist(consumed);
      s.buffer
        ..clear()
        ..add(remaining);
    }

    for (final f in frames) {
      final m = f as Map<String, dynamic>;
      final type = m['frame_type'] as int;
      final payload = m['payload'] as Uint8List;
      if (type == _h3FrameSettings) {
        peerSettings = h3.parse_h3_settings_frame(payload);
        peerSettingsReceived = true;
        print('✅ [h3:$alpn] peer SETTINGS: $peerSettings');
        onPeerSettings(peerSettings);
      } else {
        print(
          'ℹ️ [h3:$alpn] ignoring control frame '
          'type=0x${type.toRadixString(16)} len=${payload.length}',
        );
      }
    }
  }

  /// Subclass hook fired the first time peer SETTINGS are parsed.
  void onPeerSettings(Map<String, int> settings) {}

  void _onPeerBidiChunk(QuicStream stream, _PeerBidiStream s, Uint8List chunk) {
    s.chunks[s.incomingOffset] = chunk;
    s.incomingOffset += chunk.length;
    final extracted = h3.extract_h3_frames_from_chunks(s.chunks, s.readOffset);
    final frames = extracted['frames'] as List<dynamic>;
    s.readOffset = extracted['new_from_offset'] as int;

    for (final f in frames) {
      final m = f as Map<String, dynamic>;
      final type = m['frame_type'] as int;
      final payload = m['payload'] as Uint8List;
      if (type == _h3FrameHeaders) {
        try {
          final fields = h3.decode_qpack_header_fields(payload);
          final headers = <String, String>{
            for (final f in fields) f.name: f.value,
          };
          onRequestHeaders(stream, s.streamId, headers);
        } catch (e) {
          print('🛑 [h3:$alpn] QPACK decode failed: $e');
        }
      } else {
        print(
          'ℹ️ [h3:$alpn] ignoring request frame '
          'type=0x${type.toRadixString(16)} len=${payload.length}',
        );
      }
    }
  }

  /// Subclass hook for incoming HTTP/3 request HEADERS.
  void onRequestHeaders(
    QuicStream stream,
    int streamId,
    Map<String, String> headers,
  ) {}

  // ---------------------------------------------------------------
  // Inbound DATAGRAMs (RFC 9297)
  // ---------------------------------------------------------------

  void _onDatagram(Uint8List datagram) {
    if (datagram.isEmpty) return;
    final dynamic res = readVarInt(datagram, 0);
    if (res == null) return;
    final sessionId = res.value as int;
    final prefixLen = res.byteLength as int;
    final payload = datagram.sublist(prefixLen);
    final session = _wtSessions[sessionId];
    if (session == null) {
      print(
        '⚠️ [h3:$alpn] DATAGRAM for unknown WT session $sessionId '
        'len=${payload.length}',
      );
      return;
    }
    print('📦 [h3:$alpn] WT DATAGRAM session=$sessionId len=${payload.length}');
    session._deliverDatagram(payload);
  }

  // ---------------------------------------------------------------
  // WebTransport session management
  // ---------------------------------------------------------------

  WebTransportSession registerWtSession(int sessionId) {
    final existing = _wtSessions[sessionId];
    if (existing != null) return existing;
    final s = WebTransportSession._(sessionId, this);
    _wtSessions[sessionId] = s;
    _wtSessionsCtrl.add(s);
    return s;
  }

  WebTransportSession? wtSessionById(int id) => _wtSessions[id];
}

// ---------------------------------------------------------------
// Server-side specialisation
// ---------------------------------------------------------------

class Http3ServerProtocol extends Http3ProtocolBase {
  Http3ServerProtocol(super.conn, [super.alpn = h3Alpn]);
  @override
  void onRequestHeaders(
    QuicStream stream,
    int streamId,
    Map<String, String> headers,
  ) {
    final method = headers[':method'];
    final protocol = headers[':protocol'];
    final path = headers[':path'];

    print(
      '✅ [h3:$alpn] request streamId=$streamId '
      ':method=$method :protocol=$protocol :path=$path',
    );

    if (method == 'CONNECT' && protocol == 'webtransport') {
      // draft-ietf-webtrans-http3: accept the session.
      final responseHeaderBlock = h3.build_http3_literal_headers_frame(
        <String, String>{
          ':status': '200',
          'sec-webtransport-http3-draft': 'draft02',
        },
      );
      final framed = h3.build_h3_frames(<Map<String, dynamic>>[
        <String, dynamic>{
          'frame_type': _h3FrameHeaders,
          'payload': responseHeaderBlock,
        },
      ]);
      stream.write(framed);
      print('✅ [h3:$alpn] accepted WT session on stream $streamId');
      registerWtSession(streamId);
    } else {
      // Generic 404 for anything else.
      final responseHeaderBlock = h3.build_http3_literal_headers_frame(
        <String, String>{':status': '404'},
      );
      final framed = h3.build_h3_frames(<Map<String, dynamic>>[
        <String, dynamic>{
          'frame_type': _h3FrameHeaders,
          'payload': responseHeaderBlock,
        },
      ]);
      stream.write(framed, fin: true);
    }
  }
}

class Http3ServerProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const <String>[h3Alpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      Http3ServerProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      Http3ClientProtocol(conn);
}

// ---------------------------------------------------------------
// Client-side specialisation
// ---------------------------------------------------------------

class Http3ClientProtocol extends Http3ProtocolBase {
  /// `:authority` pseudo-header used when this client opens the
  /// extended CONNECT for WebTransport.
  String authority;
  String wtPath;
  bool _wtConnectSent = false;

  Http3ClientProtocol(
    QuicConnection conn, {
    this.authority = 'localhost',
    this.wtPath = '/wt',
    String alpn = h3Alpn,
  }) : super(conn, alpn);

  @override
  void onPeerSettings(Map<String, int> settings) {
    if (_wtConnectSent) return;
    if ((settings['SETTINGS_ENABLE_WEBTRANSPORT'] ?? 0) != 1) return;
    _wtConnectSent = true;
    _openWebTransportConnect();
  }

  Future<void> _openWebTransportConnect() async {
    final stream = await conn.openBidirectionalStream();
    final headerBlock = h3.build_http3_literal_headers_frame(<String, String>{
      ':method': 'CONNECT',
      ':scheme': 'https',
      ':authority': authority,
      ':path': wtPath,
      ':protocol': 'webtransport',
      'sec-webtransport-http3-draft02': '1',
    });
    final framed = h3.build_h3_frames(<Map<String, dynamic>>[
      <String, dynamic>{'frame_type': _h3FrameHeaders, 'payload': headerBlock},
    ]);
    stream.write(framed);
    print(
      '🚀 [h3:$alpn] sent extended CONNECT '
      'streamId=${stream.id} path=$wtPath',
    );
    // Pre-register: DATAGRAMs may arrive immediately keyed by this id.
    registerWtSession(stream.id);
  }

  @override
  void onRequestHeaders(
    QuicStream stream,
    int streamId,
    Map<String, String> headers,
  ) {
    final status = headers[':status'];
    print(
      '✅ [h3:$alpn] response streamId=$streamId :status=$status '
      'headers=$headers',
    );
  }
}

class Http3ClientProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const <String>[h3Alpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      Http3ServerProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      Http3ClientProtocol(conn);
}

/// Backwards-compatible alias used by existing call sites.
typedef Http3ProtocolFactory = Http3ServerProtocolFactory;
