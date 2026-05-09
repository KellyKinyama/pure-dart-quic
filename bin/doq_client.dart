// DNS-over-QUIC (RFC 9250) demo client. Sends one minimal query and
// prints the raw response bytes.

import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(DnsOverQuicProtocolFactory());

  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress('127.0.0.1'),
    remotePort: 4438,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'doq',
  );
  await ep.connection.ready;

  final proto = ep.protocol as DnsOverQuicClientProtocol;
  await proto.ready;

  // Minimal DNS query: ID=0, RD=1, QDCOUNT=1; "example" "com" A IN.
  final query = Uint8List.fromList([
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x07,
    0x65,
    0x78,
    0x61,
    0x6d,
    0x70,
    0x6c,
    0x65,
    0x03,
    0x63,
    0x6f,
    0x6d,
    0x00,
    0x00,
    0x01,
    0x00,
    0x01,
  ]);

  final reply = await proto.query(query);
  print('doq reply ${reply.length} bytes: $reply');

  await ep.close();
}
