// Apache-style integration test for Http3ReverseProxy.
//
// Uses dart:io HttpServer as a stand-in Apache origin (same wire
// protocol — HTTP/1.1 over TCP). Asserts the proxy:
//   * Preserves the upstream Host header (Apache uses it to pick the
//     virtual host).
//   * Streams big response bodies without OOMing.
//   * Adds the standard X-Forwarded-{For,Host,Proto} hints.
//   * Forwards POST bodies verbatim to backend handlers.
//   * Routes per-request via the resolver constructor (so one HTTP/3
//     front can fan out to multiple Apache vhosts on different ports).

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
  final p = ep.protocol as Http3ClientProtocol;
  p.autoConnectWebTransport = false;
  return p;
}

void main() {
  HttpServer? apache;
  HttpServer? apacheB;
  Http3ReverseProxy? proxy;
  late int proxyPort;
  var nextPort = 15630;

  setUp(() {
    proxyPort = nextPort++;
  });

  tearDown(() async {
    await proxy?.close();
    proxy = null;
    await apache?.close(force: true);
    await apacheB?.close(force: true);
    apache = null;
    apacheB = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  test(
    'Apache-style origin sees X-Forwarded-* and the upstream Host',
    () async {
      apache = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      apache!.listen((req) {
        // Mimic an Apache mod_status / vhost-aware handler.
        final fwdFor = req.headers.value('x-forwarded-for') ?? '';
        final fwdProto = req.headers.value('x-forwarded-proto') ?? '';
        final fwdHost = req.headers.value('x-forwarded-host') ?? '';
        final via = req.headers.value('via') ?? '';
        final host = req.headers.host ?? '';
        req.response
          ..statusCode = 200
          ..headers.contentType = ContentType('text', 'plain', charset: 'utf-8')
          ..write(
            'host=$host fwd-for=$fwdFor fwd-proto=$fwdProto '
            'fwd-host=$fwdHost via=$via',
          );
        req.response.close();
      });

      proxy = Http3ReverseProxy(
        target: Uri.parse('http://127.0.0.1:${apache!.port}'),
      );
      await proxy!.bind('127.0.0.1', proxyPort);

      final c = await _dial(proxyPort);
      final r = await c.get('/');
      expect(r.status, 200);
      final body = r.bodyAsString;
      expect(body, contains('host=127.0.0.1'));
      expect(body, contains('fwd-proto=https')); // HTTP/3 is always TLS
      expect(body, contains('fwd-host=localhost'));
      expect(body, contains('via=3 pure-dart-quic'));
    },
    timeout: _to,
  );

  test(
    'Large Apache response streams through without buffering all in memory',
    () async {
      // 256 KiB body in 4 KiB chunks — exercises the streaming path
      // (respondHeaders + repeated writeBody + endResponse).
      const chunkSize = 4 * 1024;
      const totalChunks = 64;
      final chunk = Uint8List(chunkSize)..fillRange(0, chunkSize, 0x41);

      apache = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      apache!.listen((req) async {
        req.response.statusCode = 200;
        req.response.headers
          ..contentType = ContentType('application', 'octet-stream')
          ..set('cache-control', 'no-store');
        for (var i = 0; i < totalChunks; i++) {
          req.response.add(chunk);
        }
        await req.response.close();
      });

      proxy = Http3ReverseProxy(
        target: Uri.parse('http://127.0.0.1:${apache!.port}'),
      );
      await proxy!.bind('127.0.0.1', proxyPort);

      final c = await _dial(proxyPort);
      final r = await c.get('/big');
      expect(r.status, 200);
      expect(r.body.length, chunkSize * totalChunks);
      // Spot-check the bytes — all 0x41.
      expect(r.body.first, 0x41);
      expect(r.body.last, 0x41);
      expect(r.headers['content-type'], contains('application/octet-stream'));
      expect(r.headers['cache-control'], 'no-store');
    },
    timeout: _to,
  );

  test(
    'POST body forwarded verbatim to Apache (e.g. mod_php upload)',
    () async {
      apache = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      apache!.listen((req) async {
        expect(req.method, 'POST');
        expect(req.headers.contentType?.mimeType, 'application/json');
        final body = await utf8.decoder.bind(req).join();
        final decoded = jsonDecode(body) as Map<String, dynamic>;
        req.response
          ..statusCode = 202
          ..headers.contentType = ContentType('application', 'json')
          ..write(jsonEncode({'received': decoded['msg'], 'len': body.length}));
        req.response.close();
      });

      proxy = Http3ReverseProxy(
        target: Uri.parse('http://127.0.0.1:${apache!.port}'),
      );
      await proxy!.bind('127.0.0.1', proxyPort);

      final c = await _dial(proxyPort);
      final payload = utf8.encode(jsonEncode({'msg': 'hello apache'}));
      final r = await c.request(
        'POST',
        '/api/ingest',
        headers: const {'content-type': 'application/json'},
        body: Uint8List.fromList(payload),
      );
      expect(r.status, 202);
      final j = jsonDecode(r.bodyAsString) as Map<String, dynamic>;
      expect(j['received'], 'hello apache');
      expect(j['len'], payload.length);
    },
    timeout: _to,
  );

  test('Resolver fans one HTTP/3 front-end out to two Apache vhosts', () async {
    apache = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    apacheB = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    apache!.listen((req) {
      req.response
        ..statusCode = 200
        ..write('vhost-A path=${req.uri.path}')
        ..close();
    });
    apacheB!.listen((req) {
      req.response
        ..statusCode = 200
        ..write('vhost-B path=${req.uri.path}')
        ..close();
    });

    proxy = Http3ReverseProxy.resolver(
      resolver: (req) {
        if (req.path.startsWith('/b/')) {
          return Uri.parse('http://127.0.0.1:${apacheB!.port}');
        }
        return Uri.parse('http://127.0.0.1:${apache!.port}');
      },
    );
    await proxy!.bind('127.0.0.1', proxyPort);

    final c = await _dial(proxyPort);
    final ra = await c.get('/a/page');
    final rb = await c.get('/b/page');
    expect(ra.bodyAsString, 'vhost-A path=/a/page');
    expect(rb.bodyAsString, 'vhost-B path=/b/page');
  }, timeout: _to);
}
