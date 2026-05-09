// QUIC bidi streams → TCP reverse proxy.
//
// Bridges QUIC bidirectional streams to a backend plain-TCP server.
// Each accepted QUIC bidi stream gets its own dedicated upstream
// TCP socket; bytes flow byte-for-byte in both directions. A QUIC
// stream FIN closes the write half of the TCP socket; an EOF on the
// TCP read half closes the QUIC stream's write half.
//
// Wire format:
//   QUIC stream bytes  ==  TCP byte stream   (verbatim)
//
// This is the QUIC analogue of [UdpReverseProxy] for stream-oriented
// services (HTTP/1.1 origins, SMTP, IMAP, custom binary servers, …).

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../../app/alpn_registry.dart';
import '../../app/application_protocol.dart';
import '../../transport/quic/quic_connection.dart';
import '../../transport/quic/quic_endpoint.dart';

/// ALPN advertised by the proxy and required from clients.
const String tcpProxyAlpn = 'tcp-proxy';

/// Resolves the upstream TCP target for a given accepted QUIC
/// connection.
typedef TcpProxyResolver =
    FutureOr<({InternetAddress address, int port})> Function(
      QuicConnection conn,
    );

class _TcpProxyProtocol extends ApplicationProtocol {
  @override
  final String alpn = tcpProxyAlpn;
  final QuicConnection conn;
  _TcpProxyProtocol(this.conn);

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {}
}

class _TcpProxyProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [tcpProxyAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      _TcpProxyProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      _TcpProxyProtocol(conn);
}

/// QUIC → TCP reverse proxy. Bind it on a UDP port; each accepted QUIC
/// bidi stream is bridged to one upstream TCP connection.
class TcpReverseProxy {
  final TcpProxyResolver _resolve;
  QuicServerEndpoint? _endpoint;
  final Set<_TcpBridge> _bridges = <_TcpBridge>{};

  TcpReverseProxy({required InternetAddress address, required int port})
    : _resolve = ((_) => (address: address, port: port));

  TcpReverseProxy.resolver({required TcpProxyResolver resolver})
    : _resolve = resolver;

  InternetAddress? get address => _endpoint?.udp.address;
  int? get port => _endpoint?.udp.port;

  Future<void> bind(dynamic address, int port) async {
    final addr = address is InternetAddress
        ? address
        : InternetAddress(address as String);

    final alpns = AlpnRegistry()..register(_TcpProxyProtocolFactory());

    final ep = await QuicServerEndpoint.bind(
      address: addr,
      port: port,
      alpns: alpns,
    );
    _endpoint = ep;

    ep.connections.listen(_attach);
  }

  Future<void> close() async {
    for (final b in _bridges.toList()) {
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

    conn.incomingStreams.listen((stream) async {
      final isUni = (stream.id & 0x02) != 0;
      if (isUni) return; // only bidi streams are bridged
      final target = await _resolve(conn);
      Socket upstream;
      try {
        upstream = await Socket.connect(target.address, target.port);
      } catch (_) {
        await stream.close();
        return;
      }
      final bridge = _TcpBridge(stream: stream, upstream: upstream);
      _bridges.add(bridge);
      bridge.start();
      bridge.done.future.whenComplete(() => _bridges.remove(bridge));
    });
  }
}

class _TcpBridge {
  final QuicStream stream;
  final Socket upstream;
  final Completer<void> done = Completer<void>();
  StreamSubscription<Uint8List>? _qSub;
  StreamSubscription<Uint8List>? _tSub;
  bool _closed = false;

  _TcpBridge({required this.stream, required this.upstream});

  void start() {
    // QUIC → TCP
    _qSub = stream.incoming.listen(
      (chunk) {
        try {
          upstream.add(chunk);
        } catch (_) {
          close();
        }
      },
      onDone: () async {
        try {
          await upstream.flush();
        } catch (_) {}
        try {
          await upstream.close();
        } catch (_) {}
      },
    );

    // TCP → QUIC
    _tSub = upstream.listen(
      (chunk) {
        try {
          stream.write(chunk);
        } catch (_) {
          close();
        }
      },
      onDone: () async {
        try {
          await stream.close();
        } catch (_) {}
        await close();
      },
      onError: (_) => close(),
    );
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _qSub?.cancel();
    await _tSub?.cancel();
    try {
      await upstream.close();
    } catch (_) {}
    try {
      upstream.destroy();
    } catch (_) {}
    if (!done.isCompleted) done.complete();
  }
}
