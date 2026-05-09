// End-to-end loopback test for the QUIC → TCP reverse proxy.
//
// Spins up a tiny TCP echo server, fronts it with [TcpReverseProxy],
// dials the proxy with [TcpProxyClient], and verifies bytes flow
// both ways.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 30));

void main() {
  ServerSocket? backend;
  TcpReverseProxy? proxy;
  late int proxyPort;
  var nextPort = 15430;

  setUp(() {
    proxyPort = nextPort++;
  });

  tearDown(() async {
    await proxy?.close();
    proxy = null;
    await backend?.close();
    backend = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  test('bytes flow byte-for-byte in both directions', () async {
    backend = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    backend!.listen((sock) {
      sock.listen((chunk) {
        // Reverse the chunk and send back.
        final reversed = Uint8List.fromList(chunk.reversed.toList());
        sock.add(reversed);
      });
    });

    proxy = TcpReverseProxy(
      address: InternetAddress.loopbackIPv4,
      port: backend!.port,
    );
    await proxy!.bind(InternetAddress.loopbackIPv4, proxyPort);

    final client = await TcpProxyClient.connect(
      remoteAddress: InternetAddress.loopbackIPv4,
      remotePort: proxyPort,
    );
    addTearDown(client.close);

    final stream = await client.openStream();
    final got = Completer<Uint8List>();
    stream.incoming.listen((chunk) {
      if (!got.isCompleted) got.complete(chunk);
    });

    stream.write(Uint8List.fromList([1, 2, 3, 4, 5]));

    final reply = await got.future.timeout(const Duration(seconds: 10));
    expect(reply, equals(Uint8List.fromList([5, 4, 3, 2, 1])));
  }, timeout: _to);

  test('two streams reach two independent upstream sockets', () async {
    var connCount = 0;
    backend = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    backend!.listen((sock) {
      final id = ++connCount;
      sock.listen((chunk) {
        // Tag each reply with the per-connection id so we can tell
        // them apart.
        sock.add([id, ...chunk]);
      });
    });

    proxy = TcpReverseProxy(
      address: InternetAddress.loopbackIPv4,
      port: backend!.port,
    );
    await proxy!.bind(InternetAddress.loopbackIPv4, proxyPort);

    final client = await TcpProxyClient.connect(
      remoteAddress: InternetAddress.loopbackIPv4,
      remotePort: proxyPort,
    );
    addTearDown(client.close);

    final s1 = await client.openStream();
    final s2 = await client.openStream();

    final r1 = Completer<Uint8List>();
    final r2 = Completer<Uint8List>();
    s1.incoming.listen((c) {
      if (!r1.isCompleted) r1.complete(c);
    });
    s2.incoming.listen((c) {
      if (!r2.isCompleted) r2.complete(c);
    });

    s1.write(Uint8List.fromList([0xaa]));
    s2.write(Uint8List.fromList([0xbb]));

    final got1 = await r1.future.timeout(const Duration(seconds: 10));
    final got2 = await r2.future.timeout(const Duration(seconds: 10));

    // First byte is the per-upstream-connection id (1 or 2 — order may
    // vary depending on which TCP socket connected first).
    expect({got1[0], got2[0]}, equals({1, 2}));
    expect({got1[1], got2[1]}, equals({0xaa, 0xbb}));
  }, timeout: _to);
}
