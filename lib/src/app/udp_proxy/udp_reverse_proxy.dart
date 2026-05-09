// QUIC DATAGRAM \u2192 UDP reverse proxy.
//
// Bridges QUIC unreliable DATAGRAMs (RFC 9221) to a backend plain-UDP
// server. Each accepted QUIC connection gets its own dedicated
// upstream UDP socket; inbound DATAGRAMs are forwarded verbatim and
// any reply UDP packets from the upstream are wrapped back into
// DATAGRAMs and delivered to the QUIC peer.
//
// Wire format:
//   QUIC DATAGRAM payload  ==  UDP datagram payload   (verbatim)
//
// This is the QUIC analogue of [Http3ReverseProxy]: it lets a plain
// UDP service (DNS, syslog, NTP, game protocol, \u2026) be reached over
// authenticated, congestion-controlled QUIC by a client that speaks
// the bundled `udp-proxy` ALPN.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../../app/alpn_registry.dart';
import '../../app/application_protocol.dart';
import '../../transport/quic/quic_connection.dart';
import '../../transport/quic/quic_endpoint.dart';

/// ALPN advertised by the proxy and required from clients.
const String udpProxyAlpn = 'udp-proxy';

/// Resolves the upstream UDP target for a given accepted QUIC
/// connection. Allows per-connection routing (e.g. by ALPN, peer
/// address, or auth header in a future extension).
typedef UdpProxyResolver =
    FutureOr<({InternetAddress address, int port})> Function(
      QuicConnection conn,
    );

/// Pure passthrough application protocol \u2014 disables the engine's
/// in-process HTTP/3 bootstrap so the [UdpReverseProxy] can use the
/// connection's raw DATAGRAM stream.
class _UdpProxyProtocol extends ApplicationProtocol {
  @override
  final String alpn = udpProxyAlpn;
  final QuicConnection conn;
  _UdpProxyProtocol(this.conn);

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {}
}

class _UdpProxyProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [udpProxyAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      _UdpProxyProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      _UdpProxyProtocol(conn);
}

/// QUIC \u2192 UDP reverse proxy. Bind it on a UDP port; each accepted
/// QUIC connection is bridged to one upstream UDP server.
class UdpReverseProxy {
  final UdpProxyResolver _resolve;
  QuicServerEndpoint? _endpoint;
  final Map<QuicConnection, _Bridge> _bridges = <QuicConnection, _Bridge>{};

  /// Construct a proxy that always forwards to ([address], [port]).
  UdpReverseProxy({required InternetAddress address, required int port})
    : _resolve = ((_) => (address: address, port: port));

  /// Per-connection resolver variant.
  UdpReverseProxy.resolver({required UdpProxyResolver resolver})
    : _resolve = resolver;

  InternetAddress? get address => _endpoint?.udp.address;
  int? get port => _endpoint?.udp.port;

  /// Bind the QUIC/UDP socket and start proxying.
  Future<void> bind(dynamic address, int port) async {
    final addr = address is InternetAddress
        ? address
        : InternetAddress(address as String);

    final alpns = AlpnRegistry()..register(_UdpProxyProtocolFactory());

    final ep = await QuicServerEndpoint.bind(
      address: addr,
      port: port,
      alpns: alpns,
    );
    _endpoint = ep;

    ep.connections.listen(_attach);
  }

  Future<void> close() async {
    for (final b in _bridges.values.toList()) {
      await b.close();
    }
    _bridges.clear();
    final ep = _endpoint;
    _endpoint = null;
    await ep?.close();
  }

  Future<void> _attach(QuicConnection conn) async {
    try {
      await conn.ready;
    } catch (_) {
      return;
    }
    final target = await _resolve(conn);
    final upstream = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    final bridge = _Bridge(
      conn: conn,
      upstream: upstream,
      upstreamAddress: target.address,
      upstreamPort: target.port,
    );
    _bridges[conn] = bridge;
    bridge.start();
    conn.closed.whenComplete(() {
      _bridges.remove(conn);
      bridge.close();
    });
  }
}

class _Bridge {
  final QuicConnection conn;
  final RawDatagramSocket upstream;
  final InternetAddress upstreamAddress;
  final int upstreamPort;
  StreamSubscription<RawSocketEvent>? _upSub;
  StreamSubscription<Uint8List>? _dgSub;
  bool _closed = false;

  _Bridge({
    required this.conn,
    required this.upstream,
    required this.upstreamAddress,
    required this.upstreamPort,
  });

  void start() {
    // QUIC \u2192 UDP
    _dgSub = conn.datagrams.listen((payload) {
      if (_closed) return;
      try {
        upstream.send(payload, upstreamAddress, upstreamPort);
      } catch (_) {
        // Drop; UDP is best-effort.
      }
    });

    // UDP \u2192 QUIC
    _upSub = upstream.listen((event) {
      if (_closed || event != RawSocketEvent.read) return;
      final dg = upstream.receive();
      if (dg == null) return;
      try {
        conn.sendDatagram(dg.data);
      } catch (_) {}
    });
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _dgSub?.cancel();
    await _upSub?.cancel();
    upstream.close();
  }
}
