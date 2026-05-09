// End-to-end loopback test for SIP-over-QUIC.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 30));

void main() {
  QuicServerEndpoint? server;
  late int port;
  var nextPort = 15530;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  test('REGISTER is parsed and answered with 200 OK', () async {
    final alpns = AlpnRegistry()..register(SipOverQuicProtocolFactory());
    server = await QuicServerEndpoint.bind(
      address: InternetAddress.loopbackIPv4,
      port: port,
      alpns: alpns,
    );

    server!.connections.listen((conn) async {
      final proto = server!.protocolFor(conn);
      if (proto is SipOverQuicServerProtocol) {
        proto.transactions.listen((tx) async {
          expect(tx.request.method, 'REGISTER');
          expect(tx.request.requestUri, 'sip:localhost');
          expect(tx.request.header('Call-ID'), 'demo@localhost');
          expect(
            tx.request.header('CONTACT'),
            '<sip:alice@127.0.0.1;transport=quic>',
          ); // case-insensitive
          await tx.respond(
            SipMessage.response(
              statusCode: 200,
              reasonPhrase: 'OK',
              headers: [
                MapEntry('Via', tx.request.header('Via')!),
                MapEntry('From', tx.request.header('From')!),
                MapEntry('To', tx.request.header('To')!),
                MapEntry('Call-ID', tx.request.header('Call-ID')!),
                MapEntry('CSeq', tx.request.header('CSeq')!),
              ],
            ),
          );
        });
      }
    });

    final clientAlpns = AlpnRegistry()..register(SipOverQuicProtocolFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: InternetAddress.loopbackIPv4,
      remotePort: port,
      authority: 'localhost',
      alpns: clientAlpns,
      alpn: 'sip',
    );
    addTearDown(ep.close);
    await ep.connection.ready;

    final proto = ep.protocol as SipOverQuicClientProtocol;
    await proto.ready;

    final responses = await proto.send(
      SipMessage.request(
        method: 'REGISTER',
        requestUri: 'sip:localhost',
        headers: const [
          MapEntry('Via', 'SIP/2.0/QUIC localhost;branch=z9hG4bK-1'),
          MapEntry('Max-Forwards', '70'),
          MapEntry('From', '<sip:alice@localhost>;tag=a1'),
          MapEntry('To', '<sip:alice@localhost>'),
          MapEntry('Call-ID', 'demo@localhost'),
          MapEntry('CSeq', '1 REGISTER'),
          MapEntry('Contact', '<sip:alice@127.0.0.1;transport=quic>'),
        ],
      ),
    );

    final got = await responses.first.timeout(const Duration(seconds: 10));
    expect(got.kind, SipMessageKind.response);
    expect(got.statusCode, 200);
    expect(got.reasonPhrase, 'OK');
    expect(got.header('Call-ID'), 'demo@localhost');
  }, timeout: _to);

  test(
    'INVITE with SDP body round-trips with 100 Trying then 200 OK',
    () async {
      final alpns = AlpnRegistry()..register(SipOverQuicProtocolFactory());
      server = await QuicServerEndpoint.bind(
        address: InternetAddress.loopbackIPv4,
        port: port,
        alpns: alpns,
      );

      final sdp = utf8.encode(
        'v=0\r\n'
        'o=alice 2890844526 2890844526 IN IP4 127.0.0.1\r\n'
        's=demo\r\n'
        'c=IN IP4 127.0.0.1\r\n'
        't=0 0\r\n'
        'm=audio 49170 RTP/AVP 0\r\n',
      );

      server!.connections.listen((conn) async {
        final proto = server!.protocolFor(conn);
        if (proto is SipOverQuicServerProtocol) {
          proto.transactions.listen((tx) async {
            expect(tx.request.method, 'INVITE');
            expect(tx.request.header('Content-Type'), 'application/sdp');
            expect(tx.request.body, equals(sdp));
            // Provisional 100 Trying.
            await tx.respond(
              SipMessage.response(
                statusCode: 100,
                reasonPhrase: 'Trying',
                headers: [
                  MapEntry('Via', tx.request.header('Via')!),
                  MapEntry('From', tx.request.header('From')!),
                  MapEntry('To', tx.request.header('To')!),
                  MapEntry('Call-ID', tx.request.header('Call-ID')!),
                  MapEntry('CSeq', tx.request.header('CSeq')!),
                ],
              ),
            );
            // Final 200 OK echoing the SDP body back.
            await tx.respond(
              SipMessage.response(
                statusCode: 200,
                reasonPhrase: 'OK',
                headers: [
                  MapEntry('Via', tx.request.header('Via')!),
                  MapEntry('From', tx.request.header('From')!),
                  MapEntry('To', '${tx.request.header('To')!};tag=server-1'),
                  MapEntry('Call-ID', tx.request.header('Call-ID')!),
                  MapEntry('CSeq', tx.request.header('CSeq')!),
                  const MapEntry('Content-Type', 'application/sdp'),
                ],
                body: Uint8List.fromList(sdp),
              ),
            );
          });
        }
      });

      final clientAlpns = AlpnRegistry()
        ..register(SipOverQuicProtocolFactory());
      final ep = await QuicClientEndpoint.connect(
        remoteAddress: InternetAddress.loopbackIPv4,
        remotePort: port,
        authority: 'localhost',
        alpns: clientAlpns,
        alpn: 'sip',
      );
      addTearDown(ep.close);
      await ep.connection.ready;

      final proto = ep.protocol as SipOverQuicClientProtocol;
      await proto.ready;

      final responses = await proto.send(
        SipMessage.request(
          method: 'INVITE',
          requestUri: 'sip:bob@localhost',
          headers: const [
            MapEntry('Via', 'SIP/2.0/QUIC localhost;branch=z9hG4bK-2'),
            MapEntry('Max-Forwards', '70'),
            MapEntry('From', '<sip:alice@localhost>;tag=a2'),
            MapEntry('To', '<sip:bob@localhost>'),
            MapEntry('Call-ID', 'invite@localhost'),
            MapEntry('CSeq', '1 INVITE'),
            MapEntry('Contact', '<sip:alice@127.0.0.1;transport=quic>'),
            MapEntry('Content-Type', 'application/sdp'),
          ],
          body: Uint8List.fromList(sdp),
        ),
      );

      final collected = <SipMessage>[];
      final done = Completer<void>();
      responses.listen((r) {
        collected.add(r);
        if ((r.statusCode ?? 0) >= 200) done.complete();
      });

      await done.future.timeout(const Duration(seconds: 10));
      expect(collected.length, greaterThanOrEqualTo(2));
      expect(collected.first.statusCode, 100);
      expect(collected.last.statusCode, 200);
      expect(collected.last.header('Content-Type'), 'application/sdp');
      expect(collected.last.body, equals(sdp));
    },
    timeout: _to,
  );
}
