# Media-over-QUIC (MoQ-style)

ALPN: `moq-00`. Module: [`lib/src/app/media/media_protocol.dart`](../lib/src/app/media/media_protocol.dart).

A minimal MoQ-style transport: a control bidi stream carries
`SETUP` / `SUBSCRIBE` / `ANNOUNCE` messages, and media objects are pushed
as QUIC DATAGRAMs (RFC 9221).

## Server (publisher)

```dart
final alpns = AlpnRegistry()..register(MediaOverQuicProtocolFactory());

final endpoint = await QuicServerEndpoint.bind(
  address: InternetAddress('127.0.0.1'),
  port: 4436,
  alpns: alpns,
);

endpoint.connections.listen((conn) {
  final proto = endpoint.protocol;
  if (proto is MediaOverQuicServerProtocol) {
    proto.subscribes.listen((track) {
      // start producing frames for `track`
      Timer.periodic(const Duration(milliseconds: 100), (t) {
        proto.publish(MoqObject(
          trackId: 1,
          groupId: 0,
          objectId: t.tick,
          payload: Uint8List.fromList('frame ${t.tick}'.codeUnits),
        ));
      });
    });
  }
});
```

Full demo: [bin/moq_server.dart](../bin/moq_server.dart).

## Client (subscriber)

```dart
final alpns = AlpnRegistry()..register(MediaOverQuicProtocolFactory());
final ep = await QuicClientEndpoint.connect(
  remoteAddress: InternetAddress('127.0.0.1'),
  remotePort: 4436,
  authority: 'localhost',
  alpns: alpns,
  alpn: 'moq-00',
);
await ep.connection.ready;

final proto = ep.protocol as MediaOverQuicClientProtocol;
await proto.setupCompleted;
proto.subscribe('video/0');
proto.objects.listen((obj) => print('frame g=${obj.groupId} o=${obj.objectId}'));
```

Full demo: [bin/moq_client.dart](../bin/moq_client.dart).

## Wire format

Control stream messages (length-prefixed):

| Type | Direction | Fields |
|---|---|---|
| `SETUP` | both | version, role |
| `ANNOUNCE` | server → client | track namespace |
| `SUBSCRIBE` | client → server | track name |

Each `MoqObject` is sent as one DATAGRAM with a tiny header (track / group /
object IDs as varints, then payload).

## Limitations

- Single track / single subscriber per connection.
- No FETCH, no relays, no priority.
- Datagrams may be lost (no retransmission); object ordering is best-effort.
