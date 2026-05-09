// SIP-over-QUIC demo server.
//
// Listens on UDP 127.0.0.1:4440 with ALPN `sip`. Acts as a tiny
// in-memory registrar: REGISTER → 200 OK, OPTIONS → 200 OK, anything
// else → 501 Not Implemented.

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(SipOverQuicProtocolFactory());

  final endpoint = await QuicServerEndpoint.bind(
    address: InternetAddress('127.0.0.1'),
    port: 4440,
    alpns: alpns,
  );

  print(
    'sip server listening on ${endpoint.udp.address.address}:'
    '${endpoint.udp.port}  alpns=${alpns.advertisedAlpns}',
  );

  endpoint.connections.listen((conn) {
    final proto = endpoint.protocolFor(conn);
    if (proto is SipOverQuicServerProtocol) {
      proto.transactions.listen((tx) async {
        print('▶ sip ${tx.request}');
        final headers = <MapEntry<String, String>>[
          if (tx.request.header('Via') != null)
            MapEntry('Via', tx.request.header('Via')!),
          if (tx.request.header('From') != null)
            MapEntry('From', tx.request.header('From')!),
          if (tx.request.header('To') != null)
            MapEntry('To', tx.request.header('To')!),
          if (tx.request.header('Call-ID') != null)
            MapEntry('Call-ID', tx.request.header('Call-ID')!),
          if (tx.request.header('CSeq') != null)
            MapEntry('CSeq', tx.request.header('CSeq')!),
        ];
        switch (tx.request.method) {
          case 'REGISTER':
          case 'OPTIONS':
            await tx.respond(
              SipMessage.response(
                statusCode: 200,
                reasonPhrase: 'OK',
                headers: headers,
              ),
            );
            break;
          default:
            await tx.respond(
              SipMessage.response(
                statusCode: 501,
                reasonPhrase: 'Not Implemented',
                headers: headers,
              ),
            );
        }
      });
    }
  });
}
