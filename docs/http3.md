# HTTP/3 (`Http3Server`)

ALPN: `h3`. Module: [`lib/src/app/h3/h3_protocol.dart`](../lib/src/app/h3/h3_protocol.dart) and the framework wrapper [`http3_server.dart`](../lib/src/app/h3/http3_server.dart).

`Http3Server` is a route-based HTTP/3 server in the spirit of `dart:io`'s
`HttpServer` or `shelf`. It hides QUIC, ALPN and endpoint setup.

## Server

```dart
import 'package:pure_dart_quic/pure_dart_quic.dart';

final app = Http3Server();

app.get('/',           (req) => req.respondText(200, 'hi'));
app.get('/json',       (req) => req.respondJson(200, {'ok': true}));
app.get('/greet/:name',(req) => req.respondText(200, 'Hello ${req.params['name']}'));
app.get('/static/*',   (req) => req.respondText(200, 'asset ${req.params['*']}'));

app.post('/echo', (req) async {
  final body = await req.readAsString();
  req.respondText(200, body);
});

app.fallback = (req) => req.respondJson(404, {'error': 'not_found'});

await app.bind('127.0.0.1', 4433);
```

Full demo: [bin/http_server.dart](../bin/http_server.dart).

### Routing

- `:param` — single segment capture, available via `req.params['param']`.
- `*` (trailing only) — wildcard tail, available via `req.params['*']`.
- Methods: `get`, `post`, `put`, `delete`, `patch`, `head`, `options`, `any`.
- First route that matches wins; otherwise `fallback` (defaults to plain 404).

### Request API (`Http3Request`)

| Member | Purpose |
|---|---|
| `method`, `path`, `authority`, `scheme` | Pseudo-headers |
| `headers` | `Map<String,String>` of regular headers |
| `params` | Captured route params (extension) |
| `body` | `Future<Uint8List>` of full body |
| `readAsString()` | Convenience UTF-8 decode |
| `respondText/Json/Html(status, body)` | One-shot response helpers |
| `respond(status, headers, body)` | Lower-level response |

## Client

```dart
final alpns = AlpnRegistry()..register(Http3ProtocolFactory());
final ep = await QuicClientEndpoint.connect(
  remoteAddress: InternetAddress('127.0.0.1'),
  remotePort: 4433,
  authority: 'localhost',
  alpns: alpns,
  alpn: 'h3',
);
await ep.connection.ready;

final h3 = ep.protocol as Http3ClientProtocol;
final resp = await h3.request('GET', '/json');
print('${resp.status} ${resp.headers['content-type']} ${resp.bodyAsString}');
```

`Http3Response` exposes `status`, `headers`, `body` (`Uint8List`) and
`bodyAsString`. `h3.get(path)` is shorthand for
`h3.request('GET', path)`.

## Notes & limitations

- Requests are HEADERS + (optional) DATA + FIN on a single client-initiated
  bidi stream.
- QPACK is the static table only — no dynamic table.
- Server pushes are not implemented.
- Trailers are not implemented.
- Body responses are buffered in memory (not streamed).
