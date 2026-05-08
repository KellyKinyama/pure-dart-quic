# pure_dart_quic — Application Guide

This folder documents the high-level application APIs that ship on top of the
QUIC engine. Each protocol is a self-contained module under
[../lib/src/app/](../lib/src/app/) and is selected at the TLS layer via ALPN.

| Protocol | ALPN | Module | Demo (server / client) | Doc |
|---|---|---|---|---|
| HTTP/3 | `h3` | [`h3_protocol.dart`](../lib/src/app/h3/h3_protocol.dart) | [`bin/http_server.dart`](../bin/http_server.dart) / [`bin/client.dart`](../bin/client.dart) | [http3.md](http3.md) |
| WebTransport | `h3`, `wt`, `webtransport` | [`h3_protocol.dart`](../lib/src/app/h3/h3_protocol.dart) | [`bin/server.dart`](../bin/server.dart) / [`bin/client.dart`](../bin/client.dart) | [webtransport.md](webtransport.md) |
| XMPP-over-QUIC | `xmpp-quic` | [`xmpp_protocol.dart`](../lib/src/app/xmpp/xmpp_protocol.dart) | [`bin/xmpp_server.dart`](../bin/xmpp_server.dart) / [`bin/xmpp_client.dart`](../bin/xmpp_client.dart) | [xmpp.md](xmpp.md) |
| Media-over-QUIC | `moq-00` | [`media_protocol.dart`](../lib/src/app/media/media_protocol.dart) | [`bin/moq_server.dart`](../bin/moq_server.dart) / [`bin/moq_client.dart`](../bin/moq_client.dart) | [moq.md](moq.md) |
| SIP-over-QUIC | `sip` (stub) | [`sip_protocol.dart`](../lib/src/app/sip/sip_protocol.dart) | — | [sip.md](sip.md) |

## Architecture in one picture

```
┌──────────────────────────────────────────────────────────────┐
│  App framework (Http3Server, WebTransportServer, …)          │  <- docs here
├──────────────────────────────────────────────────────────────┤
│  ApplicationProtocol (h3, wt, xmpp-quic, moq-00, sip, …)     │
│  selected by AlpnRegistry from TLS ALPN                      │
├──────────────────────────────────────────────────────────────┤
│  QuicConnection / QuicStream  (open uni/bidi, datagrams)     │
├──────────────────────────────────────────────────────────────┤
│  QUIC engine (TLS 1.3, packet, frames, header protection)    │
├──────────────────────────────────────────────────────────────┤
│  UdpTransport (dart:io RawDatagramSocket)                    │
└──────────────────────────────────────────────────────────────┘
```

Apps consume only the top two layers. They never touch UDP, packets,
keys or stream IDs directly.

## Common pattern

Server:

```dart
final alpns = AlpnRegistry()..register(MyProtocolFactory());
final ep = await QuicServerEndpoint.bind(
  address: InternetAddress('127.0.0.1'),
  port: 4433,
  alpns: alpns,
);
ep.connections.listen((conn) { /* per-connection setup */ });
```

Client:

```dart
final alpns = AlpnRegistry()..register(MyProtocolFactory());
final ep = await QuicClientEndpoint.connect(
  remoteAddress: InternetAddress('127.0.0.1'),
  remotePort: 4433,
  authority: 'localhost',
  alpns: alpns,
  alpn: 'my-alpn',
);
await ep.connection.ready;
final proto = ep.protocol as MyProtocolClient;
```

The HTTP/3 and WebTransport modules add a higher-level **app framework**
(`Http3Server`, `WebTransportServer`) so you don't even see the endpoint.

## Running the demos

```powershell
dart pub get

# HTTP/3
dart run bin\http_server.dart        # 127.0.0.1:4433
dart run bin\client.dart

# WebTransport
dart run bin\server.dart             # 127.0.0.1:4433
dart run bin\client.dart

# XMPP-over-QUIC
dart run bin\xmpp_server.dart        # 127.0.0.1:4435
dart run bin\xmpp_client.dart

# Media-over-QUIC
dart run bin\moq_server.dart         # 127.0.0.1:4436
dart run bin\moq_client.dart
```

Only one server can bind a given UDP port at a time — kill the previous
one first if you switch demos on the same port.

## Caveats

This is research / demo quality:

- single connection at a time, no congestion control
- no Retry, no path migration, no 0-RTT
- self-signed cert generated at startup
- bare `print()` logging
