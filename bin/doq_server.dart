// DNS-over-QUIC (RFC 9250) demo server.
//
// Listens on UDP 127.0.0.1:4438 with ALPN `doq`. For every received
// query it returns a fake-but-well-formed response made by copying
// the query header and setting QR=1 and an empty answer section.

import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(DnsOverQuicProtocolFactory());

  final endpoint = await QuicServerEndpoint.bind(
    address: InternetAddress('127.0.0.1'),
    port: 4438,
    alpns: alpns,
  );

  print(
    'doq server listening on ${endpoint.udp.address.address}:'
    '${endpoint.udp.port}  alpns=${alpns.advertisedAlpns}',
  );

  endpoint.connections.listen((conn) {
    final proto = endpoint.protocolFor(conn);
    if (proto is DnsOverQuicServerProtocol) {
      proto.queries.listen((ex) {
        // Build a minimal response: copy the 12-byte DNS header from
        // the query, set QR=1, RCODE=0, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0.
        final reply = Uint8List(12);
        reply.setRange(0, 12, ex.query.sublist(0, 12));
        reply[2] |= 0x80; // QR
        reply[3] = 0x00; // clear RCODE
        reply[6] = 0;
        reply[7] = 0; // ANCOUNT
        reply[8] = 0;
        reply[9] = 0; // NSCOUNT
        reply[10] = 0;
        reply[11] = 0; // ARCOUNT
        ex.respond(reply);
      });
    }
  });
}
