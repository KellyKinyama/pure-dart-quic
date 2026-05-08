// HTTP/3 application example using the high-level Http3Server API.
//
// No QUIC, ALPN or endpoint plumbing visible — just routes and
// handlers, much like dart:io's HttpServer or shelf.

import 'dart:convert';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final app = Http3Server();

  app.get('/', (req) {
    req.respondHtml(
      200,
      '<!doctype html><h1>pure_dart_quic</h1>'
      '<p>HTTP/3 over QUIC, served from Dart.</p>',
    );
  });

  app.get('/hello', (req) => req.respondText(200, 'Hello, World!\n'));

  app.get('/json', (req) {
    req.respondJson(200, <String, dynamic>{
      'server': 'pure_dart_quic',
      'method': req.method,
      'path': req.path,
      'authority': req.authority,
    });
  });

  // Path parameter: /greet/Alice -> "Hello, Alice!"
  app.get('/greet/:name', (req) {
    req.respondText(200, 'Hello, ${req.params['name']}!\n');
  });

  // Echo the POST body back as text.
  app.post('/echo', (req) async {
    final body = await req.readAsString();
    req.respondText(200, body);
  });

  // Wildcard route: /static/* captures the rest of the path.
  app.get('/static/*', (req) {
    req.respondText(200, 'static asset: ${req.params['*']}\n');
  });

  // Custom 404 instead of the default.
  app.fallback = (req) {
    req.respondJson(404, <String, dynamic>{
      'error': 'not_found',
      'method': req.method,
      'path': req.path,
    });
  };

  await app.bind('127.0.0.1', 4433);
  print(
    'http/3 app listening on ${app.address?.address}:${app.port}\n'
    '  GET  /\n'
    '  GET  /hello\n'
    '  GET  /json\n'
    '  GET  /greet/:name\n'
    '  GET  /static/*\n'
    '  POST /echo',
  );
  // Avoid an unused-import warning for jsonEncode in some lints.
  jsonEncode(<String, dynamic>{});
}
