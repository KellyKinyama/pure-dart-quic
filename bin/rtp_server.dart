// RTP-over-QUIC (RoQ) example server.
//
// Listens on UDP 127.0.0.1:4439. For every accepted connection it
// emits ~50 synthetic RTP packets at 50 Hz as QUIC DATAGRAMs on
// flow_id=0 (audio-like), and also publishes 5 packets on a reliable
// uni stream on flow_id=1 (e.g. SDP-like metadata).
//
// "We have no UDP on the web" — this is the canonical workaround:
// open one QUIC connection to a roq-aware server and ship RTP over
// the existing TLS-protected datagram channel.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(RtpOverQuicProtocolFactory());

  final endpoint = await QuicServerEndpoint.bind(
    address: InternetAddress('127.0.0.1'),
    port: 4439,
    alpns: alpns,
  );

  print(
    'roq server listening on ${endpoint.udp.address.address}:'
    '${endpoint.udp.port}  alpns=${alpns.advertisedAlpns}',
  );

  endpoint.connections.listen((conn) async {
    print('accepted QUIC connection (alpn=${conn.alpn})');
    final proto = endpoint.protocolFor(conn);
    if (proto is! RtpOverQuicProtocol) return;
    await conn.ready;
    // Let the client wire its `incoming` listener after handshake.
    await Future<void>.delayed(const Duration(milliseconds: 50));

    proto.incoming.listen((p) {
      print('▶ roq server received $p');
    });

    // DATAGRAM burst: simulated audio frames @ 50 Hz on flow 0.
    const ssrcAudio = 0x12345678;
    var seq = 0;
    var ts = 0;
    Timer.periodic(const Duration(milliseconds: 20), (t) {
      if (seq >= 50) {
        t.cancel();
        return;
      }
      proto.sendDatagram(
        0,
        RtpPacket(
          marker: seq == 0,
          payloadType: 96,
          sequenceNumber: seq,
          timestamp: ts,
          ssrc: ssrcAudio,
          payload: Uint8List.fromList(
            List<int>.generate(160, (i) => (seq + i) & 0xff),
          ),
        ),
      );
      seq++;
      ts += 160;
    });

    // Reliable uni-stream burst on flow 1.
    final packets = <RtpPacket>[
      for (var i = 0; i < 5; i++)
        RtpPacket(
          marker: false,
          payloadType: 97,
          sequenceNumber: i,
          timestamp: i * 960,
          ssrc: 0xfeedface,
          payload: Uint8List.fromList(utf8Bytes('roq-frame-$i')),
        ),
    ];
    await proto.sendStream(1, packets);
    print('roq server sent ${packets.length} packets on flow 1 (stream)');
  });
}

List<int> utf8Bytes(String s) => s.codeUnits;
