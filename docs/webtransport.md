# WebTransport (`WebTransportServer`)

ALPN: `h3` (also accepts `wt`, `webtransport` aliases).
Module: [`lib/src/app/h3/h3_protocol.dart`](../lib/src/app/h3/h3_protocol.dart),
framework wrapper [`http3_server.dart`](../lib/src/app/h3/http3_server.dart).

WebTransport rides on HTTP/3 via `CONNECT :protocol=webtransport`. The
framework exposes a route-based API parallel to `Http3Server`.

## WT-only server

```dart
import 'package:pure_dart_quic/pure_dart_quic.dart';

final wt = WebTransportServer();

wt.route('/echo', (s) {
  s.datagrams.listen(s.sendDatagram);

  s.incomingUnidirectionalStreams.listen((peer) async {
    final bytes = await _drain(peer);
    final out = await s.openUnidirectionalStream();
    out.write(bytes, fin: true);
  });

  s.incomingBidirectionalStreams.listen((peer) async {
    final bytes = await _drain(peer);
    peer.write(bytes, fin: true);
  });
});

wt.route('/greet/:name', (s) {
  s.sendDatagram(Uint8List.fromList(utf8.encode('hello, ${s.params['name']}')));
});

await wt.bind('127.0.0.1', 4433);
```

Full demo: [bin/server.dart](../bin/server.dart).

## Combined HTTP/3 + WebTransport

```dart
final app = Http3Server();
app.get('/', (r) => r.respondText(200, 'hi'));
app.webtransport('/wt', (s) { /* … */ });
await app.bind('127.0.0.1', 4433);
```

Both APIs share one QUIC endpoint. Unmatched WT CONNECT paths are auto-rejected
with `:status: 404`.

## Session API (`WebTransportSession`)

| Member | Purpose |
|---|---|
| `sessionId` | Underlying H3 stream ID |
| `path` | The CONNECT `:path` (route key) |
| `params` | Captured route params (extension) |
| `datagrams` | `Stream<Uint8List>` of incoming WT datagrams |
| `sendDatagram(bytes)` | Outgoing WT datagram |
| `incomingUnidirectionalStreams` | `Stream<WebTransportStream>` |
| `incomingBidirectionalStreams` | `Stream<WebTransportStream>` |
| `openUnidirectionalStream()` | New server-initiated uni |
| `openBidirectionalStream()` | New server-initiated bidi |

`WebTransportStream` exposes `incoming` (Stream<Uint8List>),
`write(bytes, {fin})` and `close()`.

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
h3.wtPath = '/echo';                       // CONNECT path

h3.webTransportSessions.listen((wt) {
  wt.datagrams.listen((d) => print('echo: $d'));
  wt.sendDatagram(Uint8List.fromList([1, 2, 3, 4]));
});
```

The client opens exactly one WT session at the path set in
`Http3ClientProtocol.wtPath` (default `/wt`).

## Wire details (FYI)

- Datagrams: `varint(quarterStreamId) ‖ payload` (RFC 9297 + WT mapping).
- Uni stream framing: `varint(0x54) ‖ varint(sessionId) ‖ data`.
- Bidi stream framing: `varint(0x41) ‖ varint(sessionId) ‖ data`.
- SETTINGS: server advertises `SETTINGS_ENABLE_WEBTRANSPORT=1`,
  `SETTINGS_H3_DATAGRAM=1`, `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`.

## Limitations

- Only one WT session per QUIC connection from the client side (driven by
  `wtPath`).
- Session-level CLOSE_WEBTRANSPORT_SESSION capsule not implemented.
- No congestion control, no flow-control window updates beyond defaults.
