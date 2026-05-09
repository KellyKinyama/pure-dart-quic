// Socket.IO-style API on top of WebTransport-over-HTTP/3.
//
// Provides the familiar Socket.IO programming model — event-based
// publish/subscribe with rooms, broadcast, namespaces, and acks —
// without the Engine.IO HTTP polling / WebSocket fallback layer.
// Every Socket.IO connection rides on a single WebTransport session:
//
//   * one bidi stream per session carries length-prefixed JSON
//     packets (CONNECT / EVENT / ACK / JOIN / LEAVE / DISCONNECT)
//   * WT DATAGRAMs carry the same JSON for "volatile" emits
//     (best-effort, no ack)
//
// This is NOT wire-compatible with the canonical Engine.IO/Socket.IO
// protocol (which is HTTP/WebSocket framed). It is a faithful
// re-implementation of the **API** on top of QUIC datagrams + streams.
//
// Wire format (control stream):
//   frame := varint(jsonLen) || jsonBytes
//
// Packet JSON shape:
//   {
//     "t": <int>,            // packet type
//     "ns": "/foo",          // (CONNECT)        namespace path
//     "sid": "abc",          // (CONNECT_ACK)    server-assigned id
//     "e":  "chat",          // (EVENT)          event name
//     "a":  [ ... ],         // (EVENT|ACK)      args
//     "id": <int>,           // (EVENT|ACK)      ack id
//     "r":  "room1",         // (JOIN|LEAVE)     room name
//     "msg": "..."           // (ERROR)
//   }
//
// Packet types:
//   0 CONNECT      client -> server   open the namespace
//   1 CONNECT_ACK  server -> client   accepted, sid assigned
//   2 DISCONNECT   either             clean shutdown
//   3 EVENT        either             named event with args (+ ack)
//   4 ACK          either             reply for a previous EVENT
//   5 JOIN         client -> server   subscribe to a room
//   6 LEAVE        client -> server   unsubscribe from a room
//   7 ERROR        either             surface an error message
//
// DATAGRAM frames are a single packet JSON with no length prefix.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../../../utils.dart';
import '../../transport/quic/quic_endpoint.dart';
import '../alpn_registry.dart';
import '../h3/h3_protocol.dart';
import '../h3/http3_server.dart';

// ---------------------------------------------------------------------------
// Packet codec
// ---------------------------------------------------------------------------

const int _pktConnect = 0;
const int _pktConnectAck = 1;
const int _pktDisconnect = 2;
const int _pktEvent = 3;
const int _pktAck = 4;
const int _pktJoin = 5;
const int _pktLeave = 6;
const int _pktError = 7;

Uint8List _encode(Map<String, dynamic> json) {
  final body = utf8.encode(jsonEncode(json));
  final lenPrefix = writeVarInt(body.length);
  final out = Uint8List(lenPrefix.length + body.length);
  out.setRange(0, lenPrefix.length, lenPrefix);
  out.setRange(lenPrefix.length, out.length, body);
  return out;
}

/// Streaming decoder for length-prefixed JSON frames.
class _FrameDecoder {
  final BytesBuilder _buf = BytesBuilder();

  Iterable<Map<String, dynamic>> add(Uint8List chunk) sync* {
    _buf.add(chunk);
    while (true) {
      final bytes = _buf.toBytes();
      if (bytes.isEmpty) return;
      final hdr = readVarInt(bytes, 0);
      if (hdr == null) return;
      final total = hdr.byteLength + hdr.value;
      if (bytes.length < total) return;
      final body = bytes.sublist(hdr.byteLength, total);
      _buf.clear();
      if (bytes.length > total) _buf.add(bytes.sublist(total));
      try {
        yield jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
      } catch (e) {
        print('🛑 [socketio] dropped malformed frame: $e');
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Acks
// ---------------------------------------------------------------------------

/// Provided to event handlers when the peer requested an ack. Call
/// [send] (with optional reply args) exactly once.
class SocketIoAck {
  final void Function(List<dynamic> args) _send;
  bool _sent = false;
  SocketIoAck._(this._send);

  /// Send the ack reply. Subsequent calls are ignored.
  void send([List<dynamic> args = const <dynamic>[]]) {
    if (_sent) return;
    _sent = true;
    _send(args);
  }
}

typedef SocketIoEventHandler =
    void Function(List<dynamic> args, [SocketIoAck? ack]);

// ---------------------------------------------------------------------------
// Shared per-peer endpoint base
// ---------------------------------------------------------------------------

/// Common machinery for one Socket.IO socket — used by both server-
/// and client-side specialisations.
abstract class _SocketIoEndpointBase {
  final WebTransportSession session;

  /// The namespace this socket belongs to (e.g. `/chat`).
  final String namespace;

  /// Locally assigned id (server-side) or server-assigned id stored
  /// after CONNECT_ACK (client-side).
  String id;

  WebTransportStream? _ctrl;
  final _FrameDecoder _decoder = _FrameDecoder();
  final Map<String, List<SocketIoEventHandler>> _handlers =
      <String, List<SocketIoEventHandler>>{};
  final Map<int, Completer<List<dynamic>>> _pendingAcks =
      <int, Completer<List<dynamic>>>{};
  int _nextAckId = 1;
  final StreamController<void> _disconnectCtrl =
      StreamController<void>.broadcast();
  bool _closed = false;

  _SocketIoEndpointBase(this.session, this.namespace, this.id);

  /// Attach a control stream (from either an outbound open or an
  /// inbound accept) and start parsing frames.
  void _attachCtrl(WebTransportStream s) {
    _ctrl = s;
    s.incoming.listen(
      (chunk) {
        for (final pkt in _decoder.add(chunk)) {
          _handlePacket(pkt);
        }
      },
      onDone: _onPeerGone,
      onError: (Object e) {
        print('🛑 [socketio] ctrl error: $e');
        _onPeerGone();
      },
    );
    session.datagrams.listen((d) {
      try {
        final pkt = jsonDecode(utf8.decode(d)) as Map<String, dynamic>;
        _handlePacket(pkt);
      } catch (_) {
        /* drop malformed datagram */
      }
    });
  }

  void _writeCtrl(Map<String, dynamic> pkt) {
    final c = _ctrl;
    if (c == null) {
      print('🛑 [socketio] write before ctrl ready, dropping $pkt');
      return;
    }
    c.write(_encode(pkt));
  }

  void _writeDatagram(Map<String, dynamic> pkt) {
    session.sendDatagram(Uint8List.fromList(utf8.encode(jsonEncode(pkt))));
  }

  /// Subscribe to an event by name. Multiple handlers per event are
  /// supported and invoked in registration order.
  void on(String event, SocketIoEventHandler handler) {
    _handlers.putIfAbsent(event, () => <SocketIoEventHandler>[]).add(handler);
  }

  /// Remove [handler] from [event] (or every handler if [handler] is
  /// omitted).
  void off(String event, [SocketIoEventHandler? handler]) {
    if (handler == null) {
      _handlers.remove(event);
    } else {
      _handlers[event]?.remove(handler);
    }
  }

  /// Emit an event to the peer. If [volatile] is true the packet is
  /// sent over a DATAGRAM (lossy, low-latency); otherwise on the
  /// reliable control stream.
  void emit(
    String event, [
    List<dynamic> args = const <dynamic>[],
    bool volatile = false,
  ]) {
    final pkt = <String, dynamic>{'t': _pktEvent, 'e': event, 'a': args};
    if (volatile) {
      _writeDatagram(pkt);
    } else {
      _writeCtrl(pkt);
    }
  }

  /// Emit an event and await the peer's ack. Times out after
  /// [timeout] (default 30s) with a [TimeoutException].
  Future<List<dynamic>> emitWithAck(
    String event, [
    List<dynamic> args = const <dynamic>[],
    Duration timeout = const Duration(seconds: 30),
  ]) {
    final ackId = _nextAckId++;
    final c = Completer<List<dynamic>>();
    _pendingAcks[ackId] = c;
    _writeCtrl(<String, dynamic>{
      't': _pktEvent,
      'e': event,
      'a': args,
      'id': ackId,
    });
    return c.future.timeout(
      timeout,
      onTimeout: () {
        _pendingAcks.remove(ackId);
        throw TimeoutException('Socket.IO ack for "$event" timed out', timeout);
      },
    );
  }

  /// Stream that fires once when the peer disconnects (or the
  /// underlying WebTransport session goes away).
  Stream<void> get onDisconnect => _disconnectCtrl.stream;

  /// True after [close] has run or the peer dropped the session.
  bool get isClosed => _closed;

  /// Send a clean DISCONNECT and tear down local state.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    try {
      _writeCtrl(<String, dynamic>{'t': _pktDisconnect});
    } catch (_) {
      /* already gone */
    }
    for (final c in _pendingAcks.values) {
      if (!c.isCompleted) {
        c.completeError(StateError('Socket.IO socket closed'));
      }
    }
    _pendingAcks.clear();
    if (!_disconnectCtrl.isClosed) {
      _disconnectCtrl.add(null);
      await _disconnectCtrl.close();
    }
    try {
      await session.close();
    } catch (_) {
      /* swallow */
    }
  }

  void _onPeerGone() {
    if (_closed) return;
    _closed = true;
    for (final c in _pendingAcks.values) {
      if (!c.isCompleted) {
        c.completeError(StateError('Peer disconnected'));
      }
    }
    _pendingAcks.clear();
    if (!_disconnectCtrl.isClosed) {
      _disconnectCtrl.add(null);
      _disconnectCtrl.close();
    }
    onPeerGone();
  }

  /// Subclass hook for additional cleanup when the peer disappears.
  void onPeerGone() {}

  void _handlePacket(Map<String, dynamic> pkt) {
    final t = pkt['t'] as int? ?? -1;
    switch (t) {
      case _pktDisconnect:
        _onPeerGone();
        return;
      case _pktEvent:
        final ev = pkt['e'] as String? ?? '';
        final args = (pkt['a'] as List<dynamic>?) ?? const <dynamic>[];
        final ackId = pkt['id'] as int?;
        SocketIoAck? ack;
        if (ackId != null) {
          ack = SocketIoAck._((reply) {
            _writeCtrl(<String, dynamic>{
              't': _pktAck,
              'id': ackId,
              'a': reply,
            });
          });
        }
        final hs = _handlers[ev];
        if (hs == null || hs.isEmpty) {
          // Implicit ack for unhandled events to avoid deadlock.
          ack?.send(const <dynamic>[]);
          return;
        }
        for (final h in List<SocketIoEventHandler>.from(hs)) {
          try {
            h(args, ack);
          } catch (e, st) {
            print('🛑 [socketio] handler "$ev" threw: $e\n$st');
          }
        }
        return;
      case _pktAck:
        final ackId = pkt['id'] as int? ?? -1;
        final waiter = _pendingAcks.remove(ackId);
        if (waiter != null && !waiter.isCompleted) {
          waiter.complete((pkt['a'] as List<dynamic>?) ?? const <dynamic>[]);
        }
        return;
      case _pktError:
        print('🛑 [socketio] peer error: ${pkt['msg']}');
        return;
      default:
        onUnhandledPacket(pkt);
    }
  }

  /// Subclass hook for packet types not handled by the base class
  /// (e.g. JOIN/LEAVE on the server, CONNECT_ACK on the client).
  void onUnhandledPacket(Map<String, dynamic> pkt) {}
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Server-facing handle for a single connected Socket.IO client.
class SocketIoSocket extends _SocketIoEndpointBase {
  final SocketIoNamespace _ns;

  SocketIoSocket._(super.session, super.namespace, super.id, this._ns);

  /// Rooms this socket is currently a member of (within its namespace).
  final Set<String> rooms = <String>{};

  /// Add this socket to [room]. Future broadcasts via
  /// `namespace.to(room).emit(...)` will reach this socket.
  void join(String room) {
    if (rooms.add(room)) {
      _ns._addToRoom(room, this);
    }
  }

  /// Remove this socket from [room].
  void leave(String room) {
    if (rooms.remove(room)) {
      _ns._removeFromRoom(room, this);
    }
  }

  /// Build a chained emitter that targets a single room within this
  /// socket's namespace, **excluding** this socket. Mirrors
  /// `socket.to(room).emit(...)` from the JS client.
  SocketIoRoomEmitter to(String room) =>
      SocketIoRoomEmitter._(_ns, <String>{room}, exclude: this);

  /// Broadcast to every other socket in the same namespace
  /// (excluding this one).
  SocketIoRoomEmitter get broadcast =>
      SocketIoRoomEmitter._(_ns, null, exclude: this);

  @override
  void onPeerGone() {
    _ns._detach(this);
  }

  @override
  void onUnhandledPacket(Map<String, dynamic> pkt) {
    final t = pkt['t'] as int? ?? -1;
    if (t == _pktJoin) {
      final r = pkt['r'] as String? ?? '';
      if (r.isNotEmpty) join(r);
    } else if (t == _pktLeave) {
      final r = pkt['r'] as String? ?? '';
      if (r.isNotEmpty) leave(r);
    }
  }
}

/// Chained emit target for a set of rooms, optionally excluding a
/// specific sender. Returned by [SocketIoSocket.to] and
/// [SocketIoNamespace.to].
class SocketIoRoomEmitter {
  final SocketIoNamespace _ns;
  final Set<String>? _rooms; // null => entire namespace
  final SocketIoSocket? _exclude;

  SocketIoRoomEmitter._(this._ns, this._rooms, {SocketIoSocket? exclude})
    : _exclude = exclude;

  /// Combine this emitter with another room.
  SocketIoRoomEmitter to(String room) {
    final next = <String>{...?_rooms, room};
    return SocketIoRoomEmitter._(_ns, next, exclude: _exclude);
  }

  /// Emit [event] to the matching audience.
  void emit(
    String event, [
    List<dynamic> args = const <dynamic>[],
    bool volatile = false,
  ]) {
    _ns._broadcast(_rooms, _exclude, event, args, volatile);
  }
}

/// Server-side namespace. Tracks every connected [SocketIoSocket] for
/// a given path (e.g. `/chat`) and provides broadcast helpers.
class SocketIoNamespace {
  final String path;

  SocketIoNamespace(this.path);

  final Set<SocketIoSocket> _sockets = <SocketIoSocket>{};
  final Map<String, Set<SocketIoSocket>> _rooms =
      <String, Set<SocketIoSocket>>{};
  final StreamController<SocketIoSocket> _connectionsCtrl =
      StreamController<SocketIoSocket>.broadcast();

  /// Stream of newly connected sockets in this namespace.
  Stream<SocketIoSocket> get connections => _connectionsCtrl.stream;

  /// All sockets currently connected on this namespace.
  Iterable<SocketIoSocket> get sockets => _sockets;

  /// All known room names in this namespace.
  Iterable<String> get rooms => _rooms.keys;

  /// Sockets that are members of [room].
  Set<SocketIoSocket> socketsIn(String room) =>
      _rooms[room]?.toSet() ?? <SocketIoSocket>{};

  /// Build a chained emitter targeting [room] within this namespace.
  SocketIoRoomEmitter to(String room) =>
      SocketIoRoomEmitter._(this, <String>{room});

  /// Broadcast [event] to **every** socket in this namespace.
  void emit(
    String event, [
    List<dynamic> args = const <dynamic>[],
    bool volatile = false,
  ]) {
    _broadcast(null, null, event, args, volatile);
  }

  void _attach(SocketIoSocket s) {
    _sockets.add(s);
    _connectionsCtrl.add(s);
  }

  void _detach(SocketIoSocket s) {
    _sockets.remove(s);
    for (final room in List<String>.from(s.rooms)) {
      _removeFromRoom(room, s);
    }
  }

  void _addToRoom(String room, SocketIoSocket s) {
    _rooms.putIfAbsent(room, () => <SocketIoSocket>{}).add(s);
  }

  void _removeFromRoom(String room, SocketIoSocket s) {
    final set = _rooms[room];
    if (set == null) return;
    set.remove(s);
    if (set.isEmpty) _rooms.remove(room);
  }

  void _broadcast(
    Set<String>? roomFilter,
    SocketIoSocket? exclude,
    String event,
    List<dynamic> args,
    bool volatile,
  ) {
    Iterable<SocketIoSocket> targets;
    if (roomFilter == null || roomFilter.isEmpty) {
      targets = _sockets;
    } else {
      final out = <SocketIoSocket>{};
      for (final r in roomFilter) {
        final set = _rooms[r];
        if (set != null) out.addAll(set);
      }
      targets = out;
    }
    for (final s in targets) {
      if (identical(s, exclude)) continue;
      try {
        s.emit(event, args, volatile);
      } catch (e) {
        print('🛑 [socketio] broadcast to ${s.id} failed: $e');
      }
    }
  }

  Future<void> _close() async {
    for (final s in List<SocketIoSocket>.from(_sockets)) {
      await s.close();
    }
    _sockets.clear();
    _rooms.clear();
    if (!_connectionsCtrl.isClosed) await _connectionsCtrl.close();
  }
}

/// High-level Socket.IO server. Wraps a [WebTransportServer] and
/// manages namespaces, sockets, and rooms.
///
/// Usage:
/// ```dart
/// final io = SocketIoServer();
/// io.of('/chat').connections.listen((s) {
///   s.on('msg', (args, [ack]) {
///     io.of('/chat').emit('msg', args);   // broadcast to everyone
///     ack?.send(['ok']);
///   });
/// });
/// await io.bind('127.0.0.1', 4444);
/// ```
class SocketIoServer {
  /// WebTransport path the server listens on. Clients connect with
  /// the same value via [SocketIoClient.connect]'s `path` argument.
  final String path;

  final WebTransportServer _wt = WebTransportServer();
  final Map<String, SocketIoNamespace> _namespaces =
      <String, SocketIoNamespace>{};
  int _nextSid = 1;

  SocketIoServer({this.path = '/socket.io'});

  /// Get (or lazily create) the namespace handle for [nsPath]
  /// (e.g. `'/chat'`). Use `'/'` for the default namespace.
  SocketIoNamespace of(String nsPath) {
    final norm = nsPath.isEmpty ? '/' : nsPath;
    return _namespaces.putIfAbsent(norm, () => SocketIoNamespace(norm));
  }

  /// Bind the underlying QUIC endpoint and begin accepting clients.
  Future<void> bind(dynamic address, int port) async {
    _wt.route(path, _onWtSession);
    await _wt.bind(address, port);
  }

  /// UDP port the underlying transport is listening on (after [bind]).
  int? get port => _wt.port;

  /// IP address the underlying transport bound to (after [bind]).
  InternetAddress? get address => _wt.address;

  /// Close the server, every namespace, and every connected socket.
  Future<void> close() async {
    for (final ns in _namespaces.values) {
      await ns._close();
    }
    _namespaces.clear();
    await _wt.close();
  }

  Future<void> _onWtSession(WebTransportSession session) async {
    WebTransportStream ctrl;
    try {
      ctrl = await session.incomingBidirectionalStreams.first.timeout(
        const Duration(seconds: 10),
      );
    } catch (e) {
      print('🛑 [socketio] session bootstrap failed (no ctrl stream): $e');
      try {
        await session.close();
      } catch (_) {
        /* swallow */
      }
      return;
    }
    final decoder = _FrameDecoder();
    SocketIoSocket? socket;
    ctrl.incoming.listen(
      (chunk) {
        for (final pkt in decoder.add(chunk)) {
          if (socket == null) {
            if ((pkt['t'] as int? ?? -1) != _pktConnect) continue;
            final ns = (pkt['ns'] as String? ?? '/').isEmpty
                ? '/'
                : pkt['ns'] as String;
            final id = 'sid-${_nextSid++}';
            final s = SocketIoSocket._(session, ns, id, of(ns));
            s._ctrl = ctrl;
            ctrl.write(
              _encode(<String, dynamic>{
                't': _pktConnectAck,
                'sid': id,
                'ns': ns,
              }),
            );
            session.datagrams.listen((d) {
              try {
                s._handlePacket(
                  jsonDecode(utf8.decode(d)) as Map<String, dynamic>,
                );
              } catch (_) {
                /* drop malformed datagram */
              }
            });
            of(ns)._attach(s);
            socket = s;
            print(
              '✅ [socketio] new socket id=$id ns=$ns '
              'sessionId=${session.sessionId}',
            );
          } else {
            socket!._handlePacket(pkt);
          }
        }
      },
      onDone: () => socket?._onPeerGone(),
      onError: (Object e) {
        print('🛑 [socketio] ctrl error: $e');
        socket?._onPeerGone();
      },
    );
  }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Client-side Socket.IO connection (one namespace per instance).
///
/// Usage:
/// ```dart
/// final io = await SocketIoClient.connect(
///   host: '127.0.0.1', port: 4444, namespace: '/chat',
/// );
/// io.on('msg', (args, [_]) => print(args));
/// io.emit('msg', ['hello']);
/// final reply = await io.emitWithAck('ping', ['x']);
/// await io.disconnect();
/// ```
class SocketIoClient extends _SocketIoEndpointBase {
  final QuicClientEndpoint _endpoint;
  final Completer<void> _connected = Completer<void>();

  SocketIoClient._(
    WebTransportSession session,
    String namespace,
    this._endpoint,
  ) : super(session, namespace, '');

  /// Future that completes once the server returns CONNECT_ACK.
  Future<void> get ready => _connected.future;

  /// Open a new Socket.IO connection over WebTransport.
  ///
  /// * [host], [port] — UDP target.
  /// * [namespace] — the Socket.IO namespace (default `/`).
  /// * [path] — WebTransport path the server is listening on
  ///   (default `/socket.io`, matching [SocketIoServer.path]).
  /// * [authority] — `:authority` pseudo-header (default `localhost`).
  static Future<SocketIoClient> connect({
    required String host,
    required int port,
    String namespace = '/',
    String path = '/socket.io',
    String authority = 'localhost',
    Duration timeout = const Duration(seconds: 15),
  }) async {
    final alpns = AlpnRegistry()..register(Http3ProtocolFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: InternetAddress(host),
      remotePort: port,
      authority: authority,
      alpns: alpns,
      alpn: 'h3',
    );
    final h3 = ep.protocol as Http3ClientProtocol;
    h3.wtPath = path;

    // Subscribe BEFORE awaiting ready (broadcast stream).
    final sessC = Completer<WebTransportSession>();
    final sessSub = h3.webTransportSessions.listen((s) {
      if (!sessC.isCompleted) sessC.complete(s);
    });
    // ignore: unawaited_futures
    sessC.future.whenComplete(sessSub.cancel);

    await ep.connection.ready;
    final session = await sessC.future.timeout(timeout);

    final client = SocketIoClient._(session, namespace, ep);
    final ctrl = await session.openBidirectionalStream();
    client._attachCtrl(ctrl);
    client._writeCtrl(<String, dynamic>{'t': _pktConnect, 'ns': namespace});
    await client.ready.timeout(timeout);
    return client;
  }

  @override
  void onUnhandledPacket(Map<String, dynamic> pkt) {
    final t = pkt['t'] as int? ?? -1;
    if (t == _pktConnectAck) {
      id = pkt['sid'] as String? ?? '';
      if (!_connected.isCompleted) _connected.complete();
    }
  }

  /// Join [room]. The server adds this client's [SocketIoSocket] to
  /// the named room.
  void join(String room) {
    _writeCtrl(<String, dynamic>{'t': _pktJoin, 'r': room});
  }

  /// Leave [room].
  void leave(String room) {
    _writeCtrl(<String, dynamic>{'t': _pktLeave, 'r': room});
  }

  @override
  Future<void> close() async {
    await super.close();
    try {
      await _endpoint.close();
    } catch (_) {
      /* swallow */
    }
  }

  /// Alias for [close], matching the JS Socket.IO API.
  Future<void> disconnect() => close();
}

/// Factory registration for Socket.IO is not required: the protocol
/// rides on top of the standard `h3` ALPN. This export exists for
/// symmetry with the other modules in [pure_dart_quic].
class SocketIoOverWtProtocolFactory {
  SocketIoOverWtProtocolFactory._();
}
