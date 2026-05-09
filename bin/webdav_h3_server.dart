// WebDAV-over-HTTP/3 example server.
//
// Listens on UDP 127.0.0.1:4439 with ALPN `h3`, exposes an in-memory
// WebDAV namespace using standard HTTP/3 verbs (GET, PUT, MKCOL,
// PROPFIND, COPY, MOVE, DELETE, OPTIONS).

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final store = InMemoryWebDavStore();
  final dav = WebDavHttp3Server(store.handler);
  await dav.bind(InternetAddress('127.0.0.1'), 4439);
  print('webdav/h3 server listening on ${dav.address?.address}:${dav.port}');
}
