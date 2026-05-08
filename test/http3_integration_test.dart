// End-to-end loopback tests for the high-level Http3Server API.
//
// Each test binds a fresh server on a unique loopback port, dials it
// from a QuicClientEndpoint, and asserts on the Http3Response.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 30));

Future<Http3ClientProtocol> _dial(int port) async {
  final alpns = AlpnRegistry()..register(Http3ProtocolFactory());
  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress.loopbackIPv4,
    remotePort: port,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'h3',
  );
  await ep.connection.ready;
  final p = ep.protocol;
  if (p is! Http3ClientProtocol) {
    throw StateError('expected Http3ClientProtocol, got $p');
  }
  // Don't issue a WT CONNECT during plain HTTP tests.
  p.autoConnectWebTransport = false;
  return p;
}

void main() {
  Http3Server? server;
  late int port;
  var nextPort = 14430;

  setUp(() async {
    port = nextPort++;
    server = Http3Server();
  });

  tearDown(() async {
    await server?.close();
    server = null;
    // Brief settle so the next bind doesn't race the OS releasing the port.
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  test('GET / returns text body', () async {
    server!.get('/', (req) => req.respondText(200, 'hello'));
    await server!.bind('127.0.0.1', port);

    final c = await _dial(port);
    final r = await c.get('/');
    expect(r.status, 200);
    expect(r.headers['content-type'], contains('text/plain'));
    expect(r.bodyAsString, 'hello');
  }, timeout: _to);

  test('GET /json returns JSON body', () async {
    server!.get('/json', (req) => req.respondJson(200, {'ok': true, 'n': 7}));
    await server!.bind('127.0.0.1', port);

    final c = await _dial(port);
    final r = await c.get('/json');
    expect(r.status, 200);
    expect(r.headers['content-type'], contains('application/json'));
    final decoded = jsonDecode(r.bodyAsString) as Map<String, dynamic>;
    expect(decoded['ok'], true);
    expect(decoded['n'], 7);
  }, timeout: _to);

  test('path parameters are captured', () async {
    server!.get('/greet/:name', (req) {
      req.respondText(200, 'hi ${req.params['name']}');
    });
    await server!.bind('127.0.0.1', port);

    final c = await _dial(port);
    final r = await c.get('/greet/Alice');
    expect(r.status, 200);
    expect(r.bodyAsString, 'hi Alice');
  }, timeout: _to);

  test('wildcard segment captures the tail', () async {
    server!.get('/static/*', (req) {
      req.respondText(200, 'asset=${req.params['*']}');
    });
    await server!.bind('127.0.0.1', port);

    final c = await _dial(port);
    final r = await c.get('/static/img/logo.png');
    expect(r.status, 200);
    expect(r.bodyAsString, 'asset=img/logo.png');
  }, timeout: _to);

  test('default fallback returns 404', () async {
    await server!.bind('127.0.0.1', port);

    final c = await _dial(port);
    final r = await c.get('/missing');
    expect(r.status, 404);
    expect(r.headers['content-type'], contains('text/plain'));
  }, timeout: _to);

  test('custom fallback overrides 404', () async {
    server!.fallback = (req) =>
        req.respondJson(418, {'error': 'teapot', 'path': req.path});
    await server!.bind('127.0.0.1', port);

    final c = await _dial(port);
    final r = await c.get('/anything');
    expect(r.status, 418);
    final body = jsonDecode(r.bodyAsString) as Map<String, dynamic>;
    expect(body['error'], 'teapot');
    expect(body['path'], '/anything');
  }, timeout: _to);

  test('multiple sequential requests on one connection', () async {
    server!
      ..get('/a', (r) => r.respondText(200, 'A'))
      ..get('/b', (r) => r.respondText(200, 'B'))
      ..get('/c', (r) => r.respondText(200, 'C'));
    await server!.bind('127.0.0.1', port);

    final c = await _dial(port);
    final ra = await c.get('/a');
    final rb = await c.get('/b');
    final rc = await c.get('/c');
    expect(ra.bodyAsString, 'A');
    expect(rb.bodyAsString, 'B');
    expect(rc.bodyAsString, 'C');
  }, timeout: _to);

  test('handler exception produces 500', () async {
    server!.get('/boom', (_) {
      throw StateError('boom');
    });
    await server!.bind('127.0.0.1', port);

    final c = await _dial(port);
    final r = await c.get('/boom');
    expect(r.status, 500);
  }, timeout: _to);

  test('async handler can read POST body', () async {
    server!.post('/echo', (req) async {
      final body = await req.readAsString();
      req.respondText(200, 'echo:$body');
    });
    await server!.bind('127.0.0.1', port);

    final c = await _dial(port);
    final r = await c.request(
      'POST',
      '/echo',
      body: Uint8List.fromList(utf8.encode('payload')),
    );
    expect(r.status, 200);
    expect(r.bodyAsString, 'echo:payload');
  }, timeout: _to);
}
