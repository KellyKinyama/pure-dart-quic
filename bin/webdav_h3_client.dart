// WebDAV-over-HTTP/3 example client (uses this repo's Http3ClientProtocol).

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()..register(Http3ProtocolFactory());

  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress('127.0.0.1'),
    remotePort: 4439,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'h3',
  );
  await ep.connection.ready;
  print('webdav/h3 client handshake complete');

  final h3 = ep.protocol as Http3ClientProtocol;
  h3.autoConnectWebTransport = false;
  final dav = WebDavHttp3Client(h3);

  print('OPTIONS / -> ${(await dav.options('/')).headers}');
  print('MKCOL /docs -> ${(await dav.mkcol('/docs')).status}');
  final put = await dav.put(
    '/docs/hello.txt',
    Uint8List.fromList(utf8.encode('Hello over WebDAV/H3\n')),
    contentType: 'text/plain',
  );
  print('PUT /docs/hello.txt -> ${put.status}');
  final got = await dav.get('/docs/hello.txt');
  print('GET /docs/hello.txt -> ${got.status} body=${utf8.decode(got.body)}');
  final pf = await dav.propfind('/docs');
  print('PROPFIND /docs -> ${pf.status}\n${utf8.decode(pf.body)}');

  await ep.close();
}
