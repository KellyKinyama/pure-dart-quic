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
import 'dart:convert';
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
// WebTransport bidirectional stream prefix (draft-ietf-webtrans-http3-02
// §4.2): the first bytes of a WT bidi stream are
// varint(0x41) varint(sessionId) followed by opaque application bytes.
const int _wtBidiFrameType = 0x41;

const int _h3FrameSettings = 0x04;
const int _h3FrameHeaders = 0x01;
const int _h3FrameData = 0x00;

const Map<String, int> _defaultSettings = <String, int>{
  'SETTINGS_QPACK_MAX_TABLE_CAPACITY': 0,
  'SETTINGS_QPACK_BLOCKED_STREAMS': 0,
  'SETTINGS_ENABLE_CONNECT_PROTOCOL': 1,
  'SETTINGS_ENABLE_WEBTRANSPORT': 1,
  'SETTINGS_H3_DATAGRAM': 1,
};

/// One unidirectional WebTransport stream. Wraps the underlying
/// QUIC stream and exposes it to application code without the
/// `varint(0x54) varint(sessionId)` framing prefix.
class WebTransportStream {
  final int streamId;
  final QuicStream _quicStream;
  final StreamController<Uint8List> _incomingCtrl =
      StreamController<Uint8List>();

  WebTransportStream._(this.streamId, this._quicStream);

  /// Application-level payload bytes (no WT framing).
  Stream<Uint8List> get incoming => _incomingCtrl.stream;

  /// Write opaque bytes onto the underlying QUIC stream.
  void write(Uint8List data, {bool fin = false}) {
    _quicStream.write(data, fin: fin);
  }

  void _deliver(Uint8List chunk) {
    if (chunk.isNotEmpty) _incomingCtrl.add(chunk);
  }

  void _close() {
    if (!_incomingCtrl.isClosed) _incomingCtrl.close();
  }
}

/// Application handle for a WebTransport session established over an
/// extended-CONNECT request stream.
class WebTransportSession {
  /// HTTP/3 request stream id on which CONNECT was issued. The stream
  /// id is also the WebTransport session id used to multiplex
  /// DATAGRAMs (RFC 9297 + draft-ietf-webtrans-http3).
  final int sessionId;

  /// `:path` from the extended CONNECT request that opened this
  /// session. Empty string if not known (e.g. client-initiated where
  /// the value wasn't surfaced to the protocol layer).
  final String path;

  final Http3ProtocolBase _owner;

  final StreamController<Uint8List> _datagrams = StreamController<Uint8List>();
  final StreamController<WebTransportStream> _incomingUniCtrl =
      StreamController<WebTransportStream>.broadcast();
  final StreamController<WebTransportStream> _incomingBidiCtrl =
      StreamController<WebTransportStream>.broadcast();
  final Map<int, WebTransportStream> _peerUniStreams =
      <int, WebTransportStream>{};
  final Map<int, WebTransportStream> _peerBidiStreams =
      <int, WebTransportStream>{};

  WebTransportSession._(this.sessionId, this._owner, {this.path = ''});

  /// Inbound WebTransport DATAGRAMs for this session.
  Stream<Uint8List> get datagrams => _datagrams.stream;

  /// Inbound peer-initiated WebTransport unidirectional streams.
  Stream<WebTransportStream> get incomingUnidirectionalStreams =>
      _incomingUniCtrl.stream;

  /// Inbound peer-initiated WebTransport bidirectional streams.
  Stream<WebTransportStream> get incomingBidirectionalStreams =>
      _incomingBidiCtrl.stream;

  /// Send a WebTransport DATAGRAM (RFC 9297 wire format:
  /// varint session_id || payload).
  void sendDatagram(Uint8List payload) {
    final framed = Uint8List.fromList(<int>[
      ...writeVarInt(sessionId),
      ...payload,
    ]);
    _owner.conn.sendDatagram(framed);
  }

  /// Open a new WebTransport unidirectional stream toward the peer.
  /// Writes the `varint(0x54) varint(sessionId)` framing prefix; the
  /// returned [WebTransportStream.write] appends opaque bytes after it.
  Future<WebTransportStream> openUnidirectionalStream() async {
    final qs = await _owner.conn.openUnidirectionalStream();
    final prefix = Uint8List.fromList(<int>[
      ...writeVarInt(_wtStreamTypeUni),
      ...writeVarInt(sessionId),
    ]);
    qs.write(prefix);
    return WebTransportStream._(qs.id, qs);
  }

  /// Open a new WebTransport bidirectional stream toward the peer.
  /// Writes the `varint(0x41) varint(sessionId)` (WEBTRANSPORT_STREAM)
  /// prefix; the rest of the stream is opaque application bytes.
  Future<WebTransportStream> openBidirectionalStream() async {
    final qs = await _owner.conn.openBidirectionalStream();
    final prefix = Uint8List.fromList(<int>[
      ...writeVarInt(_wtBidiFrameType),
      ...writeVarInt(sessionId),
    ]);
    qs.write(prefix);
    return WebTransportStream._(qs.id, qs);
  }

  void _deliverDatagram(Uint8List payload) {
    _datagrams.add(payload);
  }

  WebTransportStream _registerPeerUniStream(int streamId, QuicStream qs) {
    final existing = _peerUniStreams[streamId];
    if (existing != null) return existing;
    final wts = WebTransportStream._(streamId, qs);
    _peerUniStreams[streamId] = wts;
    _incomingUniCtrl.add(wts);
    return wts;
  }

  void _closePeerUniStream(int streamId) {
    final s = _peerUniStreams.remove(streamId);
    s?._close();
  }

  WebTransportStream _registerPeerBidiStream(int streamId, QuicStream qs) {
    final existing = _peerBidiStreams[streamId];
    if (existing != null) return existing;
    final wts = WebTransportStream._(streamId, qs);
    _peerBidiStreams[streamId] = wts;
    _incomingBidiCtrl.add(wts);
    return wts;
  }

  void _closePeerBidiStream(int streamId) {
    final s = _peerBidiStreams.remove(streamId);
    s?._close();
  }

  Future<void> close() async {
    for (final s in _peerUniStreams.values) {
      s._close();
    }
    _peerUniStreams.clear();
    for (final s in _peerBidiStreams.values) {
      s._close();
    }
    _peerBidiStreams.clear();
    await _datagrams.close();
    await _incomingUniCtrl.close();
    await _incomingBidiCtrl.close();
  }
}

class _PeerUniStream {
  final int streamId;
  final BytesBuilder buffer = BytesBuilder();
  int? streamType;
  // For type=0x54 WebTransport uni streams, the session id varint
  // immediately follows the type prefix.
  int? wtSessionId;
  WebTransportStream? wtStream;

  _PeerUniStream(this.streamId);
}

class _PeerBidiStream {
  final int streamId;
  final Map<int, Uint8List> chunks = <int, Uint8List>{};
  int readOffset = 0;
  int incomingOffset = 0;

  // null = haven't decided yet, 'h3' = HTTP/3 request, 'wt' = WebTransport bidi.
  String? mode;
  // For 'wt' mode only.
  int? wtSessionId;
  WebTransportStream? wtStream;
  // Used while mode is undecided so we can sniff the prefix without
  // disturbing the H3 chunk map.
  final BytesBuilder _sniffBuffer = BytesBuilder();

  // Server-side body plumbing: when the request handler is dispatched,
  // the protocol attaches a sink that receives DATA payloads and a
  // final empty chunk with fin=true once the stream closes.
  void Function(Uint8List chunk, bool fin)? bodySink;

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
        (chunk) => _onPeerUniChunk(stream, s, chunk),
        onDone: () {
          // Notify any WT uni stream consumer that the peer FIN'd.
          if (s.wtStream != null && s.wtSessionId != null) {
            final session = _wtSessions[s.wtSessionId!];
            session?._closePeerUniStream(id);
          }
          _peerUniStreams.remove(id);
        },
      );
    } else {
      final s = _PeerBidiStream(id);
      _peerBidiStreams[id] = s;
      stream.incoming.listen(
        (chunk) => _onPeerBidiChunk(stream, s, chunk),
        onDone: () {
          if (s.mode == 'wt' && s.wtSessionId != null) {
            final session = _wtSessions[s.wtSessionId!];
            session?._closePeerBidiStream(id);
          }
          // Signal end-of-body to any subscribed request handler.
          s.bodySink?.call(Uint8List(0), true);
          s.bodySink = null;
          _peerBidiStreams.remove(id);
        },
      );
    }
  }

  void _onPeerUniChunk(QuicStream stream, _PeerUniStream s, Uint8List chunk) {
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
        _consumeWtUniBytes(stream, s);
        break;
      default:
        s.buffer.clear();
    }
  }

  void _consumeWtUniBytes(QuicStream stream, _PeerUniStream s) {
    // Step 2 (once): read the WT session id varint that follows the
    // 0x54 stream-type prefix.
    if (s.wtSessionId == null) {
      final view = s.buffer.toBytes();
      final dynamic res = readVarInt(view, 0);
      if (res == null) return; // need more bytes
      s.wtSessionId = res.value as int;
      final prefixLen = res.byteLength as int;
      final remaining = Uint8List.sublistView(view, prefixLen);
      s.buffer
        ..clear()
        ..add(remaining);
      final session = _wtSessions[s.wtSessionId!];
      if (session == null) {
        print(
          '⚠️ [h3:$alpn] WT uni stream ${s.streamId} for unknown '
          'session ${s.wtSessionId}',
        );
        s.buffer.clear();
        return;
      }
      s.wtStream = session._registerPeerUniStream(s.streamId, stream);
      print(
        '📥 [h3:$alpn] WT uni stream ${s.streamId} '
        'attached to session ${s.wtSessionId}',
      );
    }

    // Step 3: forward any buffered (and future) opaque bytes.
    final wts = s.wtStream;
    if (wts == null) {
      s.buffer.clear();
      return;
    }
    final pending = s.buffer.toBytes();
    if (pending.isNotEmpty) {
      wts._deliver(Uint8List.fromList(pending));
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
    // Decide stream mode on first bytes: WT bidi streams start with
    // varint(0x41) varint(sessionId); H3 request streams start with
    // any other frame type (typically HEADERS = 0x01).
    if (s.mode == null) {
      s._sniffBuffer.add(chunk);
      final view = s._sniffBuffer.toBytes();
      final dynamic firstVi = readVarInt(view, 0);
      if (firstVi == null) return; // need more bytes
      final firstType = firstVi.value as int;
      if (firstType == _wtBidiFrameType) {
        final dynamic sidVi = readVarInt(view, firstVi.byteLength as int);
        if (sidVi == null) return; // need more bytes
        final consumed =
            (firstVi.byteLength as int) + (sidVi.byteLength as int);
        s.mode = 'wt';
        s.wtSessionId = sidVi.value as int;
        final session = _wtSessions[s.wtSessionId!];
        if (session == null) {
          print(
            '⚠️ [h3:$alpn] WT bidi stream ${s.streamId} for unknown '
            'session ${s.wtSessionId}',
          );
          s._sniffBuffer.clear();
          return;
        }
        s.wtStream = session._registerPeerBidiStream(s.streamId, stream);
        print(
          '📥 [h3:$alpn] WT bidi stream ${s.streamId} '
          'attached to session ${s.wtSessionId}',
        );
        // Forward any application bytes that arrived after the prefix.
        final remaining = Uint8List.sublistView(view, consumed);
        s._sniffBuffer.clear();
        if (remaining.isNotEmpty) {
          s.wtStream!._deliver(Uint8List.fromList(remaining));
        }
        return;
      } else {
        s.mode = 'h3';
        // Replay sniffed bytes into the H3 chunk map at offset 0.
        s.chunks[0] = view;
        s.incomingOffset = view.length;
        s._sniffBuffer.clear();
        _consumeH3BidiBytes(stream, s);
        return;
      }
    }

    if (s.mode == 'wt') {
      final wts = s.wtStream;
      if (wts == null) return;
      wts._deliver(chunk);
      return;
    }

    // H3 request stream path.
    s.chunks[s.incomingOffset] = chunk;
    s.incomingOffset += chunk.length;
    _consumeH3BidiBytes(stream, s);
  }

  void _consumeH3BidiBytes(QuicStream stream, _PeerBidiStream s) {
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
      } else if (type == _h3FrameData) {
        s.bodySink?.call(payload, false);
      } else {
        print(
          'ℹ️ [h3:$alpn] ignoring request frame '
          'type=0x${type.toRadixString(16)} len=${payload.length}',
        );
      }
    }
  }

  /// Internal: server-side hook used to attach a request body sink to
  /// the inbound bidi stream so DATA frames can be reassembled.
  void attachRequestBodySink(
    int streamId,
    void Function(Uint8List chunk, bool fin) sink,
  ) {
    final s = _peerBidiStreams[streamId];
    if (s != null) s.bodySink = sink;
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

  WebTransportSession registerWtSession(int sessionId, {String path = ''}) {
    final existing = _wtSessions[sessionId];
    if (existing != null) return existing;
    final s = WebTransportSession._(sessionId, this, path: path);
    _wtSessions[sessionId] = s;
    _wtSessionsCtrl.add(s);
    return s;
  }

  WebTransportSession? wtSessionById(int id) => _wtSessions[id];
}

// ---------------------------------------------------------------
// Server-side specialisation
// ---------------------------------------------------------------

/// One inbound HTTP/3 request handed to a [Http3ServerProtocol]
/// request handler. Use [respond] to send the response (HEADERS +
/// optional DATA + FIN) on the same stream.
class Http3Request {
  /// `:method` pseudo-header (e.g. `GET`).
  final String method;

  /// `:path` pseudo-header (e.g. `/index.html`).
  final String path;

  /// `:scheme` pseudo-header (typically `https`).
  final String scheme;

  /// `:authority` pseudo-header (host:port).
  final String authority;

  /// All received request headers (including pseudo-headers).
  final Map<String, String> headers;

  /// Underlying QUIC request stream.
  final QuicStream stream;

  /// QUIC stream id (== [stream].id).
  final int streamId;

  /// Future that completes with the full request body once the peer
  /// FINs the stream. Empty for bodyless requests.
  final Future<Uint8List> body;

  bool _responded = false;

  Http3Request._({
    required this.method,
    required this.path,
    required this.scheme,
    required this.authority,
    required this.headers,
    required this.stream,
    required this.streamId,
    required this.body,
  });

  /// Write a response: HEADERS frame (with `:status` + extra headers)
  /// followed by an optional DATA frame, then FIN the stream.
  /// Idempotent; subsequent calls are ignored.
  void respond(
    int status, {
    Map<String, String> headers = const <String, String>{},
    Uint8List? body,
  }) {
    if (_responded) return;
    _responded = true;
    final fields = <String, String>{':status': status.toString(), ...headers};
    final headerBlock = h3.build_http3_literal_headers_frame(fields);
    final frames = <Map<String, dynamic>>[
      <String, dynamic>{'frame_type': _h3FrameHeaders, 'payload': headerBlock},
      if (body != null && body.isNotEmpty)
        <String, dynamic>{'frame_type': _h3FrameData, 'payload': body},
    ];
    final framed = h3.build_h3_frames(frames);
    stream.write(framed, fin: true);
  }
}

/// Signature for an HTTP/3 application request handler.
typedef Http3RequestHandler = void Function(Http3Request request);

class Http3ServerProtocol extends Http3ProtocolBase {
  Http3ServerProtocol(super.conn, [super.alpn = h3Alpn]);

  /// Optional application request handler. Invoked for every inbound
  /// HTTP/3 request that is **not** a WebTransport CONNECT (those are
  /// routed via [webTransportAcceptor] / [webTransportSessions]).
  /// If null, non-WT requests get a 404.
  Http3RequestHandler? requestHandler;

  /// Optional WT CONNECT acceptor. Receives the request `:path` and
  /// returns true to accept (200 + session opened) or false to reject
  /// (404 + FIN). If null, all WT CONNECTs are accepted (legacy
  /// behaviour) so that listeners on [webTransportSessions] still see
  /// every incoming session.
  bool Function(String path)? webTransportAcceptor;

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
      final acceptor = webTransportAcceptor;
      final accept = acceptor == null ? true : acceptor(path ?? '/');
      if (!accept) {
        final block = h3.build_http3_literal_headers_frame(<String, String>{
          ':status': '404',
        });
        stream.write(
          h3.build_h3_frames(<Map<String, dynamic>>[
            <String, dynamic>{'frame_type': _h3FrameHeaders, 'payload': block},
          ]),
          fin: true,
        );
        print('⛔ [h3:$alpn] rejected WT session path=$path');
        return;
      }
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
      registerWtSession(streamId, path: path ?? '/');
      return;
    }

    final handler = requestHandler;
    if (handler != null) {
      final bodyBuf = BytesBuilder();
      final bodyCompleter = Completer<Uint8List>();
      attachRequestBodySink(streamId, (chunk, fin) {
        if (chunk.isNotEmpty) bodyBuf.add(chunk);
        if (fin && !bodyCompleter.isCompleted) {
          bodyCompleter.complete(bodyBuf.toBytes());
        }
      });
      final req = Http3Request._(
        method: method ?? '',
        path: path ?? '/',
        scheme: headers[':scheme'] ?? 'https',
        authority: headers[':authority'] ?? '',
        headers: headers,
        stream: stream,
        streamId: streamId,
        body: bodyCompleter.future,
      );
      try {
        handler(req);
      } catch (e, st) {
        print('🛑 [h3:$alpn] requestHandler threw: $e\n$st');
        if (!req._responded) {
          req.respond(
            500,
            headers: const <String, String>{'content-type': 'text/plain'},
            body: Uint8List.fromList(utf8.encode('Internal Server Error')),
          );
        }
      }
      return;
    }

    // Default: 404 with no body.
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

/// One inbound HTTP/3 response collected by [Http3ClientProtocol.request].
class Http3Response {
  /// `:status` parsed as an integer (0 if missing/unparseable).
  final int status;

  /// All received response headers (including `:status`).
  final Map<String, String> headers;

  /// Aggregated body bytes from all DATA frames.
  final Uint8List body;

  Http3Response._({
    required this.status,
    required this.headers,
    required this.body,
  });

  /// Body decoded as UTF-8.
  String get bodyAsString => utf8.decode(body, allowMalformed: true);
}

class Http3ClientProtocol extends Http3ProtocolBase {
  /// `:authority` pseudo-header used when this client opens HTTP/3
  /// requests or the extended CONNECT for WebTransport.
  String authority;

  /// Path used by the auto-issued WebTransport CONNECT.
  String wtPath;

  /// If true (default), automatically send a WebTransport CONNECT once
  /// peer SETTINGS advertise WT support. Set to false for plain HTTP/3
  /// clients that only want to use [request] / [get].
  bool autoConnectWebTransport;

  bool _wtConnectSent = false;

  Http3ClientProtocol(
    QuicConnection conn, {
    this.authority = 'localhost',
    this.wtPath = '/wt',
    this.autoConnectWebTransport = true,
    String alpn = h3Alpn,
  }) : super(conn, alpn);

  @override
  void onPeerSettings(Map<String, int> settings) {
    if (!autoConnectWebTransport) return;
    if (_wtConnectSent) return;
    if ((settings['SETTINGS_ENABLE_WEBTRANSPORT'] ?? 0) != 1) return;
    _wtConnectSent = true;
    _openWebTransportConnect();
  }

  /// Convenience wrapper for `request('GET', path, ...)`.
  Future<Http3Response> get(
    String path, {
    Map<String, String> headers = const <String, String>{},
  }) => request('GET', path, headers: headers);

  /// Issue a one-shot HTTP/3 request on a fresh client-initiated bidi
  /// stream. Sends HEADERS (+ optional DATA) with FIN, then collects
  /// the response (HEADERS + any DATA frames) until the server FINs
  /// the stream. The returned future completes when the response
  /// stream closes.
  Future<Http3Response> request(
    String method,
    String path, {
    Map<String, String> headers = const <String, String>{},
    Uint8List? body,
  }) async {
    final stream = await conn.openBidirectionalStream();
    final reqHeaders = <String, String>{
      ':method': method,
      ':scheme': 'https',
      ':authority': authority,
      ':path': path,
      ...headers,
    };
    final headerBlock = h3.build_http3_literal_headers_frame(reqHeaders);
    final outFrames = <Map<String, dynamic>>[
      <String, dynamic>{'frame_type': _h3FrameHeaders, 'payload': headerBlock},
      if (body != null && body.isNotEmpty)
        <String, dynamic>{'frame_type': _h3FrameData, 'payload': body},
    ];
    stream.write(h3.build_h3_frames(outFrames), fin: true);
    print(
      '🚀 [h3:$alpn] sent request streamId=${stream.id} '
      ':method=$method :path=$path',
    );

    final completer = Completer<Http3Response>();
    final chunks = <int, Uint8List>{};
    var offset = 0;
    var readOffset = 0;
    Map<String, String>? respHeaders;
    final bodyBuf = BytesBuilder();

    late StreamSubscription<Uint8List> sub;
    void finish() {
      if (completer.isCompleted) return;
      final h = respHeaders ?? <String, String>{};
      final status = int.tryParse(h[':status'] ?? '') ?? 0;
      completer.complete(
        Http3Response._(status: status, headers: h, body: bodyBuf.toBytes()),
      );
    }

    sub = stream.incoming.listen(
      (chunk) {
        chunks[offset] = chunk;
        offset += chunk.length;
        final extracted = h3.extract_h3_frames_from_chunks(chunks, readOffset);
        final frames = extracted['frames'] as List<dynamic>;
        readOffset = extracted['new_from_offset'] as int;
        for (final f in frames) {
          final m = f as Map<String, dynamic>;
          final type = m['frame_type'] as int;
          final payload = m['payload'] as Uint8List;
          if (type == _h3FrameHeaders) {
            try {
              final fields = h3.decode_qpack_header_fields(payload);
              respHeaders = <String, String>{
                for (final f in fields) f.name: f.value,
              };
              print(
                '✅ [h3:$alpn] response streamId=${stream.id} '
                ':status=${respHeaders![':status']}',
              );
            } catch (e) {
              print('🛑 [h3:$alpn] QPACK decode failed: $e');
            }
          } else if (type == _h3FrameData) {
            bodyBuf.add(payload);
          } else {
            print(
              'ℹ️ [h3:$alpn] ignoring response frame '
              'type=0x${type.toRadixString(16)} len=${payload.length}',
            );
          }
        }
      },
      onDone: () {
        finish();
        sub.cancel();
      },
      onError: (Object e, StackTrace st) {
        if (!completer.isCompleted) completer.completeError(e, st);
      },
      cancelOnError: true,
    );

    return completer.future;
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
