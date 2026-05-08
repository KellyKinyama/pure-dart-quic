// Public QUIC endpoint API.
//
// A [QuicServerEndpoint] binds a UDP socket and dispatches incoming
// datagrams to per-peer [ServerQuicConnection]s; once the handshake
// completes, the negotiated ALPN drives selection of an
// [ApplicationProtocol] from the configured [AlpnRegistry].
//
// A [QuicClientEndpoint] dials a single QUIC connection to a remote
// authority and likewise selects an application protocol via ALPN.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:hex/hex.dart';

import '../../../connection/client/quic_session3.dart';
import '../../../connection/server/quic_server_session.dart';
import '../../app/alpn_registry.dart';
import '../../app/application_protocol.dart';
import '../udp/udp_transport.dart';
import 'client_connection.dart';
import 'quic_connection.dart';
import 'server_connection.dart';

/// Server endpoint: listen on UDP and accept QUIC connections.
///
/// Multiple clients are demuxed by the source UDP 4-tuple
/// (`address:port`); each new peer gets its own [QuicServerSession]
/// + [ServerQuicConnection] + [ApplicationProtocol].
class QuicServerEndpoint {
  final UdpTransport udp;
  final AlpnRegistry alpns;

  /// Active per-peer connections, keyed by `${address}:${port}`.
  final Map<String, ServerQuicConnection> _conns =
      <String, ServerQuicConnection>{};
  final Map<ServerQuicConnection, ApplicationProtocol> _protoByConn =
      <ServerQuicConnection, ApplicationProtocol>{};

  /// Most recently accepted connection's [ApplicationProtocol]. Kept for
  /// backward compatibility with single-connection callers; new code
  /// should prefer [protocolFor] or read the protocol off the connection
  /// event in [connections].
  ApplicationProtocol? _proto;
  ApplicationProtocol? get protocol => _proto;

  /// Look up the [ApplicationProtocol] bound to a given connection.
  ApplicationProtocol? protocolFor(QuicConnection conn) =>
      conn is ServerQuicConnection ? _protoByConn[conn] : null;

  /// Snapshot of currently-active connections.
  Iterable<ServerQuicConnection> get activeConnections => _conns.values;

  StreamSubscription<UdpDatagram>? _sub;
  Timer? _idleSweep;

  /// Per-peer idle timeout. Connections with no inbound activity for
  /// longer than this are evicted from [activeConnections].
  final Duration idleTimeout;

  final StreamController<QuicConnection> _connectionsCtrl =
      StreamController<QuicConnection>.broadcast();

  QuicServerEndpoint._(this.udp, this.alpns, this.idleTimeout);

  static Future<QuicServerEndpoint> bind({
    required InternetAddress address,
    required int port,
    required AlpnRegistry alpns,
    UdpTransport? transport,
    Duration idleTimeout = const Duration(seconds: 30),
  }) async {
    final udp = transport ?? await DartUdpTransport.bind(address, port);
    final ep = QuicServerEndpoint._(udp, alpns, idleTimeout);
    ep._start();
    return ep;
  }

  /// Stream of newly-accepted QUIC connections.
  Stream<QuicConnection> get connections => _connectionsCtrl.stream;

  void _start() {
    _sub = udp.datagrams.listen(_dispatch);
    _idleSweep = Timer.periodic(
      Duration(
        milliseconds: (idleTimeout.inMilliseconds ~/ 4).clamp(500, 5000),
      ),
      (_) => _evictIdle(),
    );
  }

  void _evictIdle() {
    final now = DateTime.now();
    final dead = <String>[];
    _conns.forEach((key, conn) {
      if (now.difference(conn.lastActivity) > idleTimeout) {
        dead.add(key);
      }
    });
    for (final key in dead) {
      _evict(key);
    }
  }

  void _evict(String key) {
    final conn = _conns.remove(key);
    if (conn == null) return;
    final proto = _protoByConn.remove(conn);
    // Best-effort shutdown; ignore errors on dead peers.
    Future<void>.sync(() async {
      try {
        if (proto != null) await proto.stop();
      } catch (_) {}
      try {
        await conn.close();
      } catch (_) {}
    });
  }

  String _peerKey(InternetAddress addr, int port) => '${addr.address}:$port';

  void _dispatch(UdpDatagram dg) {
    final key = _peerKey(dg.address, dg.port);
    var conn = _conns[key];
    if (conn == null) {
      conn = _accept(dg.address, dg.port);
      _conns[key] = conn;
    }
    conn.handleDatagram(dg);
  }

  ServerQuicConnection _accept(InternetAddress addr, int port) {
    final session = QuicServerSession(socket: _rawSocketOf(udp));
    final chosenAlpn = alpns.advertisedAlpns.isNotEmpty
        ? alpns.advertisedAlpns.first
        : 'h3';
    final factory = alpns.lookup(chosenAlpn);

    final conn = ServerQuicConnection(
      engineSession: session,
      udp: udp,
      alpn: chosenAlpn,
      externalAppProtocol: factory != null,
    );

    if (factory != null) {
      final proto = factory.createServer(conn);
      _protoByConn[conn] = proto;
      _proto = proto; // latest-wins, for legacy `endpoint.protocol`
      conn.ready.then((_) => proto.start());
    }

    // Evict from the demux map when the connection closes (peer sent
    // CONNECTION_CLOSE — see ServerQuicConnection.closed).
    final peerKey = _peerKey(addr, port);
    conn.closed.then((_) {
      if (identical(_conns[peerKey], conn)) _evict(peerKey);
    });

    // Defer event emission so callers that subscribe to [connections]
    // right after [bind] returns don't miss the first peer.
    scheduleMicrotask(() => _connectionsCtrl.add(conn));
    return conn;
  }

  Future<void> close() async {
    _idleSweep?.cancel();
    _idleSweep = null;
    await _sub?.cancel();
    // Snapshot to avoid concurrent-modification when conn.closed
    // callbacks evict entries during shutdown.
    final protos = _protoByConn.values.toList();
    final conns = _conns.values.toList();
    _conns.clear();
    _protoByConn.clear();
    for (final p in protos) {
      try {
        await p.stop();
      } catch (_) {}
    }
    for (final c in conns) {
      try {
        await c.close();
      } catch (_) {}
    }
    await udp.close();
    await _connectionsCtrl.close();
  }
}

/// Client endpoint: dial a QUIC server.
class QuicClientEndpoint {
  final UdpTransport udp;
  final ClientQuicConnection connection;
  final ApplicationProtocol? protocol;
  StreamSubscription<UdpDatagram>? _sub;

  QuicClientEndpoint._(this.udp, this.connection, this.protocol);

  static Future<QuicClientEndpoint> connect({
    required InternetAddress remoteAddress,
    required int remotePort,
    required String authority,
    required AlpnRegistry alpns,
    String? alpn,
    UdpTransport? transport,
    Uint8List? initialDcid,
  }) async {
    final udp =
        transport ?? await DartUdpTransport.bind(InternetAddress.anyIPv4, 0);

    final dcid =
        initialDcid ?? Uint8List.fromList(HEX.decode("0001020304050607"));

    final session = QuicSession(dcid, _rawSocketOf(udp));
    final chosenAlpn =
        alpn ??
        (alpns.advertisedAlpns.isNotEmpty ? alpns.advertisedAlpns.first : 'h3');
    final factory = alpns.lookup(chosenAlpn);

    final conn = ClientQuicConnection(
      engineSession: session,
      udp: udp,
      alpn: chosenAlpn,
      externalAppProtocol: factory != null,
    );

    final proto = factory?.createClient(conn);
    if (proto != null) {
      conn.ready.then((_) => proto.start());
    }

    final sub = udp.datagrams.listen(conn.handleDatagram);

    session.sendClientHello(
      address: remoteAddress,
      port: remotePort,
      authority: authority,
      alpns: alpns.advertisedAlpns.isNotEmpty
          ? alpns.advertisedAlpns
          : <String>[chosenAlpn],
    );

    return QuicClientEndpoint._(udp, conn, proto).._sub = sub;
  }

  Future<void> close() async {
    await _sub?.cancel();
    await protocol?.stop();
    await connection.close();
    await udp.close();
  }
}

/// The current demo engine takes a [RawDatagramSocket] directly. Until
/// the engine is rewritten against [UdpTransport], extract the raw
/// socket from a [DartUdpTransport] when available.
RawDatagramSocket _rawSocketOf(UdpTransport udp) {
  if (udp is DartUdpTransport) return udp.rawSocket;
  throw UnsupportedError(
    'The current QUIC engine requires DartUdpTransport. '
    'Custom UdpTransport implementations need an engine refactor '
    '(see AGENTS.md → "Engine extraction").',
  );
}
