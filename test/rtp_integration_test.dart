// Regression tests for RTP-over-QUIC (RoQ) — both unit-level
// encode/decode round-trips and an end-to-end loopback test that
// exercises DATAGRAM and uni-stream transports.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 30));

void main() {
  group('RTP wire format', () {
    test('encode -> decode round-trip (no CSRC, no extension)', () {
      final p = RtpPacket(
        marker: true,
        payloadType: 96,
        sequenceNumber: 0x1234,
        timestamp: 0xdeadbeef,
        ssrc: 0xcafebabe,
        payload: Uint8List.fromList([1, 2, 3, 4, 5, 6]),
      );
      final bytes = encodeRtpPacket(p);
      // Fixed RTP header is 12 bytes.
      expect(bytes.length, 12 + 6);
      expect(bytes[0] >> 6, 2); // version
      expect((bytes[0] & 0x10) != 0, isFalse); // no extension
      expect(bytes[0] & 0x0f, 0); // CC
      expect((bytes[1] & 0x80) != 0, isTrue); // marker
      expect(bytes[1] & 0x7f, 96); // PT

      final decoded = decodeRtpPacket(bytes)!;
      expect(decoded.marker, isTrue);
      expect(decoded.payloadType, 96);
      expect(decoded.sequenceNumber, 0x1234);
      expect(decoded.timestamp, 0xdeadbeef);
      expect(decoded.ssrc, 0xcafebabe);
      expect(decoded.csrcs, isEmpty);
      expect(decoded.extension, isEmpty);
      expect(decoded.payload, p.payload);
    });

    test('round-trip with CSRC list', () {
      final p = RtpPacket(
        marker: false,
        payloadType: 0,
        sequenceNumber: 1,
        timestamp: 2,
        ssrc: 3,
        csrcs: const [0x11111111, 0x22222222, 0x33333333],
        payload: Uint8List.fromList([9, 9]),
      );
      final decoded = decodeRtpPacket(encodeRtpPacket(p))!;
      expect(decoded.csrcs, p.csrcs);
      expect(decoded.payload, p.payload);
    });

    test('decode rejects non-v2 packet', () {
      final p = RtpPacket(
        marker: false,
        payloadType: 0,
        sequenceNumber: 1,
        timestamp: 2,
        ssrc: 3,
        payload: Uint8List.fromList([1]),
      );
      final bytes = encodeRtpPacket(p);
      bytes[0] = (1 << 6) | (bytes[0] & 0x3f);
      expect(decodeRtpPacket(bytes), isNull);
    });

    test('decode rejects truncated header', () {
      expect(decodeRtpPacket(Uint8List(11)), isNull);
    });

    test('RoQ datagram round-trip carries flow id', () {
      final p = RtpPacket(
        marker: false,
        payloadType: 111,
        sequenceNumber: 7,
        timestamp: 8,
        ssrc: 9,
        payload: Uint8List.fromList([1, 2, 3]),
      );
      final dg = encodeRoqDatagram(42, p);
      final parsed = decodeRoqDatagram(dg)!;
      expect(parsed.flowId, 42);
      expect(parsed.packet.sequenceNumber, 7);
      expect(parsed.packet.payload, p.payload);
    });

    test('decodeRoqDatagram returns null on garbage', () {
      expect(decodeRoqDatagram(Uint8List.fromList([0xff])), isNull);
    });

    test('encode rejects out-of-range PT / seq', () {
      Uint8List enc(int pt, int seq) => encodeRtpPacket(
        RtpPacket(
          marker: false,
          payloadType: pt,
          sequenceNumber: seq,
          timestamp: 0,
          ssrc: 0,
          payload: Uint8List(0),
        ),
      );
      expect(() => enc(128, 0), throwsArgumentError);
      expect(() => enc(0, 0x10000), throwsArgumentError);
    });
  });

  group('RTP-over-QUIC loopback', () {
    QuicServerEndpoint? server;
    late int port;
    var nextPort = 14930;

    setUp(() {
      port = nextPort++;
    });

    tearDown(() async {
      await server?.close();
      server = null;
      await Future<void>.delayed(const Duration(milliseconds: 100));
    });

    test('client receives DATAGRAM + stream RTP from server', () async {
      final alpns = AlpnRegistry()..register(RtpOverQuicProtocolFactory());
      server = await QuicServerEndpoint.bind(
        address: InternetAddress.loopbackIPv4,
        port: port,
        alpns: alpns,
      );

      server!.connections.listen((conn) async {
        final proto = server!.protocolFor(conn);
        if (proto is! RtpOverQuicProtocol) return;
        // Wait until the client signals readiness by sending one
        // RTP packet on flow 0xff (synchronisation hack — no SETUP
        // exchange in this minimal RoQ profile).
        final ready = Completer<void>();
        proto.incoming.listen((p) {
          if (p.flowId == 0xff && !ready.isCompleted) ready.complete();
        });
        await ready.future;
        // Send 3 DATAGRAM packets on flow 0.
        for (var i = 0; i < 3; i++) {
          proto.sendDatagram(
            0,
            RtpPacket(
              marker: i == 0,
              payloadType: 96,
              sequenceNumber: i,
              timestamp: i * 160,
              ssrc: 0xaaaa,
              payload: Uint8List.fromList([0xa0 + i, 0xb0 + i]),
            ),
          );
        }
        // Send 2 packets via reliable stream on flow 1.
        await proto.sendStream(1, <RtpPacket>[
          RtpPacket(
            marker: false,
            payloadType: 97,
            sequenceNumber: 100,
            timestamp: 1000,
            ssrc: 0xbbbb,
            payload: Uint8List.fromList([1, 2, 3]),
          ),
          RtpPacket(
            marker: true,
            payloadType: 97,
            sequenceNumber: 101,
            timestamp: 2000,
            ssrc: 0xbbbb,
            payload: Uint8List.fromList([4, 5, 6, 7]),
          ),
        ]);
      });

      final clientAlpns = AlpnRegistry()
        ..register(RtpOverQuicProtocolFactory());
      final ep = await QuicClientEndpoint.connect(
        remoteAddress: InternetAddress.loopbackIPv4,
        remotePort: port,
        authority: 'localhost',
        alpns: clientAlpns,
        alpn: 'roq-09',
      );
      addTearDown(ep.close);
      await ep.connection.ready;

      final proto = ep.protocol as RtpOverQuicProtocol;
      final got = <IncomingRtpPacket>[];
      final done = Completer<void>();
      proto.incoming.listen((p) {
        if (p.flowId == 0xff) return;
        got.add(p);
        if (got.length == 5) done.complete();
      });

      // Send a single-packet ready signal on a uni stream so the
      // server knows our `incoming` listener is wired.
      await proto.sendStream(0xff, <RtpPacket>[
        RtpPacket(
          marker: false,
          payloadType: 0,
          sequenceNumber: 0,
          timestamp: 0,
          ssrc: 0,
          payload: Uint8List.fromList(const [0]),
        ),
      ]);

      await done.future.timeout(const Duration(seconds: 15));

      final datagrams = got
          .where((p) => p.transport == RtpTransport.datagram)
          .toList();
      final streamed = got
          .where((p) => p.transport == RtpTransport.stream)
          .toList();

      expect(datagrams, hasLength(3));
      expect(streamed, hasLength(2));

      // DATAGRAMs may be reordered in theory, but on loopback over
      // a single QUIC connection they are typically in order.
      datagrams.sort(
        (a, b) => a.packet.sequenceNumber.compareTo(b.packet.sequenceNumber),
      );
      for (var i = 0; i < 3; i++) {
        expect(datagrams[i].flowId, 0);
        expect(datagrams[i].packet.payloadType, 96);
        expect(datagrams[i].packet.sequenceNumber, i);
        expect(datagrams[i].packet.payload, [0xa0 + i, 0xb0 + i]);
      }

      // Stream packets must arrive in send order with flow_id=1.
      expect(streamed[0].flowId, 1);
      expect(streamed[1].flowId, 1);
      expect(streamed[0].packet.sequenceNumber, 100);
      expect(streamed[1].packet.sequenceNumber, 101);
      expect(streamed[0].packet.payload, [1, 2, 3]);
      expect(streamed[1].packet.payload, [4, 5, 6, 7]);
      expect(streamed[0].streamId, isNotNull);
      expect(streamed[0].streamId, streamed[1].streamId);
    }, timeout: _to);
  });
}
