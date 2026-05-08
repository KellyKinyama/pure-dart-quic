// WebTransport application example using the high-level
// WebTransportServer API. No QUIC, ALPN or endpoint plumbing visible.
//
// Demonstrates two routes: a generic /echo (datagrams + uni + bidi
// streams reflected back) and a /greet/:name route that pushes a
// single greeting datagram on connect.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final wt = WebTransportServer();

  wt.route('/echo', (s) {
    print('▶ wt /echo opened: id=${s.sessionId}');

    s.datagrams.listen((data) {
      print('▶ datagram echo session=${s.sessionId} len=${data.length}');
      s.sendDatagram(data);
    });

    s.incomingUnidirectionalStreams.listen((peer) {
      _drain(peer).then((bytes) async {
        print(
          '▶ uni echo session=${s.sessionId} '
          'streamId=${peer.streamId} len=${bytes.length}',
        );
        final out = await s.openUnidirectionalStream();
        out.write(bytes, fin: true);
      });
    });

    s.incomingBidirectionalStreams.listen((peer) {
      _drain(peer).then((bytes) {
        print(
          '▶ bidi echo session=${s.sessionId} '
          'streamId=${peer.streamId} len=${bytes.length}',
        );
        peer.write(bytes, fin: true);
      });
    });
  });

  wt.route('/greet/:name', (s) {
    final name = s.params['name'] ?? 'stranger';
    print('▶ wt /greet/$name opened: id=${s.sessionId}');
    s.sendDatagram(Uint8List.fromList(utf8.encode('hello, $name')));
  });

  await wt.bind('127.0.0.1', 4433);
  print(
    'webtransport app listening on ${wt.address?.address}:${wt.port}\n'
    '  /echo            — datagram + stream echo\n'
    '  /greet/:name     — pushes a hello datagram',
  );
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
