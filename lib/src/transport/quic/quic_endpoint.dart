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
class QuicServerEndpoint {
  final UdpTransport udp;
  final AlpnRegistry alpns;

  /// Currently this is a single-connection demo engine; only one
  /// [ServerQuicConnection] is alive at a time.
  ServerQuicConnection? _conn;
  ApplicationProtocol? _proto;
  StreamSubscription<UdpDatagram>? _sub;

  /// The active application protocol bound to the current connection,
  /// if any. Single-connection demo only.
  ApplicationProtocol? get protocol => _proto;

  final StreamController<QuicConnection> _connectionsCtrl =
      StreamController<QuicConnection>.broadcast();

  QuicServerEndpoint._(this.udp, this.alpns);

  static Future<QuicServerEndpoint> bind({
    required InternetAddress address,
    required int port,
    required AlpnRegistry alpns,
    UdpTransport? transport,
  }) async {
    final udp = transport ?? await DartUdpTransport.bind(address, port);
    final ep = QuicServerEndpoint._(udp, alpns);
    ep._start();
    return ep;
  }

  /// Stream of newly-accepted QUIC connections.
  Stream<QuicConnection> get connections => _connectionsCtrl.stream;

  void _start() {
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
    _conn = conn;
    // Defer so callers that subscribe to [connections] right after
    // [bind] returns don't miss this event on the broadcast stream.
    scheduleMicrotask(() => _connectionsCtrl.add(conn));

    if (factory != null) {
      _proto = factory.createServer(conn);
      conn.ready.then((_) => _proto!.start());
    }

    _sub = udp.datagrams.listen(conn.handleDatagram);
  }

  Future<void> close() async {
    await _sub?.cancel();
    await _proto?.stop();
    await _conn?.close();
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
