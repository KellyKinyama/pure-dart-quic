// End-to-end test for Http3ReverseProxy.
//
// Stands up a backend HTTP/1.1 server (dart:io HttpServer), an
// Http3ReverseProxy that forwards to it, then dials the proxy with
// the in-process HTTP/3 client and asserts the response was relayed.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http2/transport.dart' as h2;
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
  final p = ep.protocol as Http3ClientProtocol;
  p.autoConnectWebTransport = false;
  return p;
}

void main() {
  HttpServer? backend;
  Http3ReverseProxy? proxy;
  late int proxyPort;
  var nextPort = 14930;

  setUp(() {
    proxyPort = nextPort++;
  });

  tearDown(() async {
    await proxy?.close();
    proxy = null;
    await backend?.close(force: true);
    backend = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  test('GET is proxied verbatim including headers and body', () async {
    backend = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    backend!.listen((req) {
      expect(req.method, 'GET');
      expect(req.uri.path, '/hello');
      expect(req.uri.queryParameters['name'], 'alice');
      req.response
        ..statusCode = 200
        ..headers.contentType = ContentType('text', 'plain', charset: 'utf-8')
        ..headers.add('x-backend', 'yes')
        ..write('hi alice');
      req.response.close();
    });

    proxy = Http3ReverseProxy(
      target: Uri.parse('http://127.0.0.1:${backend!.port}'),
    );
    await proxy!.bind('127.0.0.1', proxyPort);

    final c = await _dial(proxyPort);
    final r = await c.get('/hello?name=alice');

    expect(r.status, 200);
    expect(r.bodyAsString, 'hi alice');
    expect(r.headers['x-backend'], 'yes');
    expect(r.headers['content-type'], contains('text/plain'));
  }, timeout: _to);

  test('POST body is forwarded to the backend', () async {
    backend = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    backend!.listen((req) async {
      expect(req.method, 'POST');
      final body = await utf8.decoder.bind(req).join();
      req.response
        ..statusCode = 201
        ..headers.contentType = ContentType('application', 'json')
        ..write(jsonEncode({'echo': body}));
      req.response.close();
    });

    proxy = Http3ReverseProxy(
      target: Uri.parse('http://127.0.0.1:${backend!.port}'),
    );
    await proxy!.bind('127.0.0.1', proxyPort);

    final c = await _dial(proxyPort);
    final r = await c.request(
      'POST',
      '/upload',
      headers: const {'content-type': 'text/plain'},
      body: Uint8List.fromList('payload-123'.codeUnits),
    );

    expect(r.status, 201);
    final j = jsonDecode(r.bodyAsString) as Map<String, dynamic>;
    expect(j['echo'], 'payload-123');
  }, timeout: _to);

  test('upstream connect failure surfaces as 502', () async {
    // No backend running. Pick a port that refuses connections.
    proxy = Http3ReverseProxy(target: Uri.parse('http://127.0.0.1:1'));
    await proxy!.bind('127.0.0.1', proxyPort);

    final c = await _dial(proxyPort);
    final r = await c.get('/');
    expect(r.status, 502);
    expect(r.bodyAsString, contains('upstream'));
  }, timeout: _to);

  test('per-request resolver picks upstream dynamically', () async {
    backend = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    backend!.listen((req) {
      req.response
        ..statusCode = 200
        ..write('routed:${req.uri.path}');
      req.response.close();
    });

    proxy = Http3ReverseProxy.resolver(
      resolver: (req) => Uri.parse('http://127.0.0.1:${backend!.port}'),
    );
    await proxy!.bind('127.0.0.1', proxyPort);

    final c = await _dial(proxyPort);
    final r = await c.get('/api/v1/items');
    expect(r.status, 200);
    expect(r.bodyAsString, 'routed:/api/v1/items');
  }, timeout: _to);

  test('h2c upstream: HTTP/2 request is multiplexed and forwarded', () async {
    // Spin up a real HTTP/2 origin (h2c with prior knowledge) using
    // package:http2's ServerTransportConnection.
    final h2Server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(h2Server.close);
    h2Server.listen((sock) {
      final conn = h2.ServerTransportConnection.viaSocket(sock);
      conn.incomingStreams.listen((stream) async {
        var path = '';
        var method = '';
        await for (final msg in stream.incomingMessages) {
          if (msg is h2.HeadersStreamMessage) {
            for (final h in msg.headers) {
              final n = ascii.decode(h.name);
              final v = ascii.decode(h.value);
              if (n == ':path') path = v;
              if (n == ':method') method = v;
            }
          }
        }
        final body = utf8.encode('h2c $method $path');
        stream.outgoingMessages.add(
          h2.HeadersStreamMessage([
            h2.Header.ascii(':status', '200'),
            h2.Header.ascii('content-type', 'text/plain'),
            h2.Header.ascii('x-upstream', 'h2c'),
          ]),
        );
        stream.outgoingMessages.add(
          h2.DataStreamMessage(body, endStream: true),
        );
        await stream.outgoingMessages.close();
      });
    });

    proxy = Http3ReverseProxy(
      target: Uri.parse('http://127.0.0.1:${h2Server.port}'),
      allowH2c: true,
    );
    await proxy!.bind('127.0.0.1', proxyPort);

    final c = await _dial(proxyPort);
    final r1 = await c.get('/h2/test');
    expect(r1.status, 200);
    expect(r1.bodyAsString, 'h2c GET /h2/test');
    expect(r1.headers['x-upstream'], 'h2c');
    expect(r1.headers['via'], '2 pure-dart-quic');

    // Second request multiplexes onto the cached h2 connection.
    final r2 = await c.get('/h2/again');
    expect(r2.status, 200);
    expect(r2.bodyAsString, 'h2c GET /h2/again');
  }, timeout: _to);
}
