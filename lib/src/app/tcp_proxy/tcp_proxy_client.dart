// Client side of the TCP-over-QUIC tunnel.
//
// Dials a [TcpReverseProxy] using ALPN `tcp-proxy`. Each call to
// [openStream] opens a fresh QUIC bidi stream which the proxy bridges
// to a fresh upstream TCP connection. Bytes written to the [QuicStream]
// flow byte-for-byte to the upstream TCP server and replies arrive on
// the stream's `incoming`.

import 'dart:async';
import 'dart:io';

import '../../app/alpn_registry.dart';
import '../../app/application_protocol.dart';
import '../../transport/quic/quic_connection.dart';
import '../../transport/quic/quic_endpoint.dart';
import 'tcp_reverse_proxy.dart';

class _TcpProxyClientProtocol extends ApplicationProtocol {
  @override
  final String alpn = tcpProxyAlpn;
  final QuicConnection conn;
  _TcpProxyClientProtocol(this.conn);

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {}
}

class _TcpProxyClientFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [tcpProxyAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      _TcpProxyClientProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      _TcpProxyClientProtocol(conn);
}

/// One open tunnel to a [TcpReverseProxy]. Open one bidi QUIC stream
/// per upstream TCP connection.
class TcpProxyClient {
  final QuicClientEndpoint _ep;

  TcpProxyClient._(this._ep);

  static Future<TcpProxyClient> connect({
    required InternetAddress remoteAddress,
    required int remotePort,
    String authority = 'localhost',
  }) async {
    final alpns = AlpnRegistry()..register(_TcpProxyClientFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: remoteAddress,
      remotePort: remotePort,
      authority: authority,
      alpns: alpns,
      alpn: tcpProxyAlpn,
    );
    await ep.connection.ready;
    return TcpProxyClient._(ep);
  }

  /// Open a fresh bidi QUIC stream. The proxy will dial a new
  /// upstream TCP connection and bridge bytes both directions.
  Future<QuicStream> openStream() => _ep.connection.openBidirectionalStream();

  Future<void> close() => _ep.close();
}
