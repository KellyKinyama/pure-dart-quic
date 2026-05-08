# XMPP-over-QUIC

ALPN: `xmpp-quic`. Module: [`lib/src/app/xmpp/xmpp_protocol.dart`](../lib/src/app/xmpp/xmpp_protocol.dart).

XMPP normally rides TCP+STARTTLS. This module muxes XMPP stanzas over a
single bidirectional QUIC stream, framed as **length-prefixed UTF-8
strings** (4-byte big-endian length, then the stanza XML).

## Server

```dart
final alpns = AlpnRegistry()..register(XmppOverQuicProtocolFactory());

final endpoint = await QuicServerEndpoint.bind(
  address: InternetAddress('127.0.0.1'),
  port: 4435,
  alpns: alpns,
);

endpoint.connections.listen((conn) {
  final proto = endpoint.protocol;
  if (proto is XmppOverQuicServerProtocol) {
    proto.opened.then((xmpp) {
      xmpp.send("<stream:features>…</stream:features>");
      xmpp.stanzas.listen((s) => xmpp.send('<echo>$s</echo>'));
    });
  }
});
```

Full demo: [bin/xmpp_server.dart](../bin/xmpp_server.dart).

## Client

```dart
final alpns = AlpnRegistry()..register(XmppOverQuicProtocolFactory());
final ep = await QuicClientEndpoint.connect(
  remoteAddress: InternetAddress('127.0.0.1'),
  remotePort: 4435,
  authority: 'localhost',
  alpns: alpns,
  alpn: 'xmpp-quic',
);
await ep.connection.ready;

final proto = ep.protocol as XmppOverQuicClientProtocol;
final xmpp = await proto.opened;

xmpp.stanzas.listen(print);
xmpp.send("<stream:stream to='localhost' xmlns='jabber:client' version='1.0'/>");
xmpp.send("<message to='alice@localhost'><body>hi</body></message>");
```

Full demo: [bin/xmpp_client.dart](../bin/xmpp_client.dart).

## API

`XmppStream`:

| Member | Purpose |
|---|---|
| `stream` | Underlying `QuicStream` |
| `send(String stanza)` | Length-prefixed write |
| `stanzas` | `Stream<String>` of received stanzas |

## Limitations

- No SASL, no TLS-channel-binding, no resource binding handshake — the
  stanza pipe is open as soon as the QUIC handshake completes.
- No XML parsing; stanzas are passed as opaque strings.
- Single stream per connection.
