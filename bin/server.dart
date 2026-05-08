// Modular QUIC server entry point.
//
// Demonstrates: UDP -> QUIC -> {HTTP/3, WebTransport} via ALPN.
//
// This file is intentionally protocol-agnostic: it stands up a QUIC +
// HTTP/3 + WebTransport endpoint and reflects every inbound payload
// back to the peer. Application protocols (chat, telemetry, etc.)
// belong in their own entry points (e.g. `bin/xoq_chat_server.dart`)
// that import this package and consume `WebTransportSession`.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()
    ..register(Http3ProtocolFactory())
    ..register(WebTransportProtocolFactory());

  final endpoint = await QuicServerEndpoint.bind(
    address: InternetAddress('127.0.0.1'),
    port: 4433,
    alpns: alpns,
  );

  print(
    'modular server listening on ${endpoint.udp.address.address}:'
    '${endpoint.udp.port}  alpns=${alpns.advertisedAlpns}',
  );

  endpoint.connections.listen((conn) {
    print('accepted QUIC connection (alpn=${conn.alpn})');
    final proto = endpoint.protocol;
    if (proto is Http3ServerProtocol) {
      proto.webTransportSessions.listen(_echoSession);
    }
    conn.ready.then((_) => print('handshake complete'));
  });
}

void _echoSession(WebTransportSession wt) {
  print('▶ wt session opened: id=${wt.sessionId}');

  // DATAGRAMs: reflect each unreliable payload back to the peer.
  wt.datagrams.listen((data) {
    print('▶ datagram echo session=${wt.sessionId} len=${data.length}');
    wt.sendDatagram(data);
  });

  // Unidirectional streams: drain to FIN, then echo on a fresh
  // server-initiated WT uni stream.
  wt.incomingUnidirectionalStreams.listen((peer) {
    _drain(peer).then((bytes) async {
      print(
        '▶ uni echo session=${wt.sessionId} '
        'streamId=${peer.streamId} len=${bytes.length}',
      );
      final out = await wt.openUnidirectionalStream();
      out.write(bytes, fin: true);
    });
  });

  // Bidirectional streams: drain to FIN, then write the response on
  // the same stream.
  wt.incomingBidirectionalStreams.listen((peer) {
    _drain(peer).then((bytes) {
      print(
        '▶ bidi echo session=${wt.sessionId} '
        'streamId=${peer.streamId} len=${bytes.length}',
      );
      peer.write(bytes, fin: true);
    });
  });
}

Future<Uint8List> _drain(WebTransportStream s) {
  final c = Completer<Uint8List>();
  final buf = BytesBuilder();
  s.incoming.listen(
    buf.add,
    onDone: () => c.complete(buf.toBytes()),
    onError: c.completeError,
    cancelOnError: true,
  );
  return c.future;
}
