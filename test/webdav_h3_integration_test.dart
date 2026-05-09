// End-to-end loopback test for WebDAV over HTTP/3.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 30));

void main() {
  WebDavHttp3Server? server;
  late int port;
  var nextPort = 14680;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  Future<WebDavHttp3Client> connect() async {
    final alpns = AlpnRegistry()..register(Http3ProtocolFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: InternetAddress.loopbackIPv4,
      remotePort: port,
      authority: 'localhost',
      alpns: alpns,
      alpn: 'h3',
    );
    addTearDown(ep.close);
    await ep.connection.ready;
    final h3 = ep.protocol as Http3ClientProtocol;
    h3.autoConnectWebTransport = false;
    return WebDavHttp3Client(h3);
  }

  Future<void> startServer() async {
    final store = InMemoryWebDavStore();
    server = WebDavHttp3Server(store.handler, logRequests: false);
    await server!.bind(InternetAddress.loopbackIPv4, port);
  }

  test('PUT then GET round-trips bytes (over h3)', () async {
    await startServer();
    final c = await connect();

    final put = await c.put(
      '/foo.txt',
      Uint8List.fromList(utf8.encode('hello world')),
      contentType: 'text/plain',
    );
    expect(put.status, 201);

    final got = await c.get('/foo.txt');
    expect(got.status, 200);
    expect(utf8.decode(got.body), 'hello world');
    expect(got.headers['content-type'], 'text/plain');
  }, timeout: _to);

  test('MKCOL + PROPFIND lists children (over h3)', () async {
    await startServer();
    final c = await connect();

    expect((await c.mkcol('/dir')).status, 201);
    expect(
      (await c.put('/dir/a.bin', Uint8List.fromList([1, 2, 3]))).status,
      201,
    );
    expect((await c.put('/dir/b.bin', Uint8List.fromList([4, 5]))).status, 201);

    final pf = await c.propfind('/dir', depth: '1');
    expect(pf.status, 207);
    final body = utf8.decode(pf.body);
    expect(body, contains('<href>/dir</href>'));
    expect(body, contains('<href>/dir/a.bin</href>'));
    expect(body, contains('<href>/dir/b.bin</href>'));
    expect(body, contains('<getcontentlength>3</getcontentlength>'));
  }, timeout: _to);

  test('OPTIONS reports DAV class', () async {
    await startServer();
    final c = await connect();

    final r = await c.options('/');
    expect(r.status, 200);
    expect(r.headers['dav'], '1');
    expect(r.headers['allow'], contains('PROPFIND'));
  }, timeout: _to);

  test('MOVE relocates a resource (over h3)', () async {
    await startServer();
    final c = await connect();

    await c.put('/x.txt', Uint8List.fromList(utf8.encode('payload')));
    final mv = await c.move('/x.txt', '/y.txt');
    expect(mv.status, anyOf(201, 204));

    expect((await c.get('/x.txt')).status, 404);
    final got = await c.get('/y.txt');
    expect(got.status, 200);
    expect(utf8.decode(got.body), 'payload');
  }, timeout: _to);
}
