// End-to-end loopback test for DNS-over-QUIC (DoQ, RFC 9250).

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 30));

void main() {
  QuicServerEndpoint? server;
  late int port;
  var nextPort = 15230;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  test('one query → one response on its own bidi stream', () async {
    final alpns = AlpnRegistry()..register(DnsOverQuicProtocolFactory());
    server = await QuicServerEndpoint.bind(
      address: InternetAddress.loopbackIPv4,
      port: port,
      alpns: alpns,
    );

    server!.connections.listen((conn) async {
      final proto = server!.protocolFor(conn);
      if (proto is DnsOverQuicServerProtocol) {
        proto.queries.listen((ex) {
          // Echo the query bytes prefixed with 0xab as a fake answer.
          final reply = Uint8List(ex.query.length + 1);
          reply[0] = 0xab;
          reply.setRange(1, reply.length, ex.query);
          ex.respond(reply);
        });
      }
    });

    final clientAlpns = AlpnRegistry()..register(DnsOverQuicProtocolFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: InternetAddress.loopbackIPv4,
      remotePort: port,
      authority: 'localhost',
      alpns: clientAlpns,
      alpn: 'doq',
    );
    addTearDown(ep.close);
    await ep.connection.ready;

    final proto = ep.protocol as DnsOverQuicClientProtocol;
    await proto.ready;

    final query = Uint8List.fromList([
      0x00, 0x00, // ID = 0 (RFC 9250 §4.2.1)
      0x01, 0x00, // RD=1
      0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // QD=1
    ]);
    final reply = await proto.query(query).timeout(const Duration(seconds: 10));
    expect(reply.length, query.length + 1);
    expect(reply[0], 0xab);
    expect(reply.sublist(1), equals(query));
  }, timeout: _to);
}
