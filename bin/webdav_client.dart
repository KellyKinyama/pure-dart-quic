// WebDAV-over-QUIC example client.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(WebDavOverQuicProtocolFactory());

  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress('127.0.0.1'),
    remotePort: 4438,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'webdav-quic',
  );

  await ep.connection.ready;
  print('webdav client handshake complete');

  final c = ep.protocol as WebDavOverQuicClientProtocol;

  print('OPTIONS / -> ${(await c.options('/')).headers}');
  print('MKCOL /docs -> ${(await c.mkcol('/docs')).status}');
  final put = await c.put(
    '/docs/hello.txt',
    Uint8List.fromList(utf8.encode('Hello over WebDAV/QUIC\n')),
    contentType: 'text/plain',
  );
  print('PUT /docs/hello.txt -> ${put.status}');
  final got = await c.get('/docs/hello.txt');
  print('GET /docs/hello.txt -> ${got.status} body=${utf8.decode(got.body)}');
  final pf = await c.propfind('/docs');
  print('PROPFIND /docs -> ${pf.status}\n${utf8.decode(pf.body)}');

  await ep.close();
}
