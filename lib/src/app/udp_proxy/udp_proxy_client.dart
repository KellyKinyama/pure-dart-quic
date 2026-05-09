// Client side of the UDP-over-QUIC tunnel.
//
// Dials a [UdpReverseProxy] using ALPN `udp-proxy` and exposes the
// QUIC DATAGRAM channel as plain send / receive streams that mirror
// the wire-side UDP service.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../../app/alpn_registry.dart';
import '../../app/application_protocol.dart';
import '../../transport/quic/quic_connection.dart';
import '../../transport/quic/quic_endpoint.dart';
import 'udp_reverse_proxy.dart';

class _UdpProxyClientProtocol extends ApplicationProtocol {
  @override
  final String alpn = udpProxyAlpn;
  final QuicConnection conn;
  _UdpProxyClientProtocol(this.conn);

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {}
}

class _UdpProxyClientFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [udpProxyAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      _UdpProxyClientProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      _UdpProxyClientProtocol(conn);
}

/// One open tunnel to a [UdpReverseProxy]. Each [send] is delivered to
/// the upstream UDP server; replies arrive on [received].
class UdpProxyClient {
  final QuicClientEndpoint _ep;

  UdpProxyClient._(this._ep);

  /// Dial the proxy at [remoteAddress]:[remotePort].
  static Future<UdpProxyClient> connect({
    required InternetAddress remoteAddress,
    required int remotePort,
    String authority = 'localhost',
  }) async {
    final alpns = AlpnRegistry()..register(_UdpProxyClientFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: remoteAddress,
      remotePort: remotePort,
      authority: authority,
      alpns: alpns,
      alpn: udpProxyAlpn,
    );
    await ep.connection.ready;
    return UdpProxyClient._(ep);
  }

  /// Inbound replies from the upstream UDP server.
  Stream<Uint8List> get received => _ep.connection.datagrams;

  /// Send one UDP datagram through the tunnel.
  void send(Uint8List payload) => _ep.connection.sendDatagram(payload);

  Future<void> close() => _ep.close();
}
