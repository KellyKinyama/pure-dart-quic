// WebDAV-over-QUIC example server.
//
// Listens on UDP 127.0.0.1:4438 with ALPN `webdav-quic`, serves an
// in-memory WebDAV namespace.

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(WebDavOverQuicProtocolFactory());

  final endpoint = await QuicServerEndpoint.bind(
    address: InternetAddress('127.0.0.1'),
    port: 4438,
    alpns: alpns,
  );

  print(
    'webdav server listening on ${endpoint.udp.address.address}:'
    '${endpoint.udp.port}  alpns=${alpns.advertisedAlpns}',
  );

  final store = InMemoryWebDavStore();

  endpoint.connections.listen((conn) {
    print('accepted QUIC connection (alpn=${conn.alpn})');
    final proto = endpoint.protocolFor(conn);
    if (proto is WebDavOverQuicServerProtocol) {
      proto.handler = (req) {
        print('▶ webdav ${req.method} ${req.path} (${req.body.length}B)');
        return store.handler(req);
      };
    }
  });
}
