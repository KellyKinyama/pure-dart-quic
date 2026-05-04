# AGENTS.md — pure_dart_quic

A pure-Dart implementation of QUIC + TLS 1.3 + HTTP/3 + WebTransport. Research / demo quality (single connection, no congestion control). See [README.md](README.md) for the protocol feature matrix.

The repo has **two layers**:

1. **Modular public API** under [lib/src/](lib/src/) — what new code should consume. Re-exported from [lib/pure_dart_quic.dart](lib/pure_dart_quic.dart).
2. **Engine internals** under [lib/connection/](lib/connection/), [lib/h3/](lib/h3/), [lib/handshake/](lib/handshake/), [lib/packet/](lib/packet/), [lib/cipher/](lib/cipher/), [lib/frames/](lib/frames/), [lib/streams/](lib/streams/) — the underlying QUIC/TLS/HTTP3 implementation that the modular API wraps.

## Run / build / test

```powershell
dart pub get

# Modular entry points (preferred)
dart run bin/server.dart                          # UDP 127.0.0.1:4433
dart run bin/client.dart

# Legacy entry points (kept; same engine)
dart run lib/connection/server/server2.dart
dart run lib/connection/client/client3.dart

dart analyze lib\src bin                          # modular layer is clean
dart analyze                                      # engine has ~105 pre-existing info-level lints
dart test                                         # only exercises stub calculate(); not meaningful for QUIC
```

There is no integration test harness — validate protocol changes by running the server and client (or a real HTTP/3 client) and reading `print()` traces.

## Modular API layout

```
lib/
├── pure_dart_quic.dart                  # public façade (export-only)
└── src/
    ├── transport/
    │   ├── udp/udp_transport.dart       # UdpTransport, DartUdpTransport
    │   └── quic/
    │       ├── quic_connection.dart     # QuicConnection, QuicStream
    │       ├── quic_endpoint.dart       # QuicServerEndpoint, QuicClientEndpoint
    │       ├── server_connection.dart   # wraps QuicServerSession
    │       └── client_connection.dart   # wraps QuicSession
    └── app/
        ├── application_protocol.dart    # ApplicationProtocol(Factory)
        ├── alpn_registry.dart           # ALPN -> factory
        ├── h3/h3_protocol.dart          # HTTP/3 + WebTransport (drives the QuicConnection API)
        ├── webtransport/                # WebTransport ALPN alias of H3 module
        ├── xmpp/                        # XMPP-over-QUIC (STUB)
        ├── media/                       # Media-over-QUIC / MoQ (STUB)
        └── sip/                         # SIP-over-QUIC (STUB)
```

Layered flow: **UDP → QUIC → {H3, WebTransport, XMPP, Media, SIP}** with ALPN-based protocol selection via `AlpnRegistry`.

When a registered factory matches the chosen ALPN, the engine's
internal HTTP/3 bootstrap is suppressed (`externalAppProtocol = true`)
and the protocol module drives SETTINGS, control stream, request
streams, and DATAGRAM I/O via `QuicConnection`. If no factory matches,
the engine still falls back to its legacy in-session HTTP/3 path.

## Engine extraction status

Done (Phases 1–3 of the original TODO):

1. ✅ Generic stream pipe extracted from the engine — `EngineQuicStream` performs offset-based reassembly and per-stream FIN/RESET (see [lib/src/transport/quic/engine_quic_stream.dart](lib/src/transport/quic/engine_quic_stream.dart)).
2. ✅ Engine emits `onIncomingStreamData(streamId, offset, data, fin)` and `onIncomingDatagram(data)` events that the adapters surface via `QuicConnection.incomingStreams` / `QuicConnection.datagrams`.
3. ✅ HTTP/3 + WebTransport moved to [lib/src/app/h3/h3_protocol.dart](lib/src/app/h3/h3_protocol.dart) and consumed via `QuicConnection`. The legacy in-session H3 code still ships and still works when no ApplicationProtocolFactory is registered.
4. ✅ DATAGRAM (RFC 9221) implemented on both sessions via `sendDatagramFrame(payload)` and surfaced through `QuicConnection.sendDatagram` / `QuicConnection.datagrams`.

Still TODO:

5. Wire real ALPN negotiation through [client_hello.dart](lib/handshake/client_hello.dart) / [server_hello.dart](lib/handshake/server_hello.dart) — the modular layer still picks the first registered ALPN as a default; the engine selects ALPN from the ClientHello internally but does not feed the choice back to the modular adapter.

The XMPP / Media / SIP stub modules can now be implemented against the
fully generic `QuicConnection` (open uni/bidi streams, send/receive
DATAGRAMs, observe inbound streams). They remain registration-only
until someone implements their wire formats.

## Canonical entry points

| Role | New (modular) | Legacy (engine direct) |
|---|---|---|
| Server `main` | [bin/server.dart](bin/server.dart) | [lib/connection/server/server2.dart](lib/connection/server/server2.dart) |
| Client `main` | [bin/client.dart](bin/client.dart) | [lib/connection/client/client3.dart](lib/connection/client/client3.dart) |
| Coalesced UDP split | `splitCoalescedPackets()` in [lib/constants.dart](lib/constants.dart) — call before per-packet handling |

## Architecture map

| Layer | Directory | Responsibility |
|---|---|---|
| UDP / packet | [lib/packet/](lib/packet/) | long/short header parsing, header protection, packet decryption |
| Frames | [lib/frames/](lib/frames/) | CRYPTO, ACK, STREAM, etc. |
| TLS 1.3 | [lib/handshake/](lib/handshake/) | ClientHello → Finished over CRYPTO frames |
| Crypto | [lib/cipher/](lib/cipher/) | AES-GCM, HKDF, X25519, P-256, ECDSA, self-signed cert helpers |
| HTTP/3 + WT | [lib/h3/](lib/h3/) | control stream, QPACK static table, WebTransport CONNECT + DATAGRAM |
| Streams | [lib/streams/](lib/streams/) | reassembly of out-of-order STREAM fragments |
| Sessions | [lib/connection/](lib/connection/) | per-connection state machines (client + server) |

## Project conventions / pitfalls

- **Numeric file suffixes are iterations, not deprecation.** [tls_msg.dart](lib/handshake/tls_msg.dart) (base class), [tls_messages.dart](lib/handshake/tls_messages.dart) (parser), [tls_messages2.dart](lib/handshake/tls_messages2.dart) (alternate parser) all coexist. Before editing one, `grep_search` for which session file imports it.
- **Logging is bare `print()`.** [log.txt](log.txt) is a captured trace, not consumed by code; do not introduce a logger framework without being asked.
- **Coalesced datagrams must be split** before per-packet processing — every receive loop in this repo calls `splitCoalescedPackets(dg.data)` and iterates.
- **Peer address is set lazily on the server** after the first datagram (see `peerSet` flag in [server2.dart](lib/connection/server/server2.dart)); preserve this pattern when modifying the receive loop.
- **`false_secrets` in [pubspec.yaml](pubspec.yaml)** whitelists [lib/cipher/cert_utils.dart](lib/cipher/cert_utils.dart) for pub.dev — it intentionally contains test key material; do not "clean it up".
- **No congestion control, no retry, no migration.** Don't add stubs for production features unless the task requests them — keep the code research-grade.
- **Dart SDK `^3.11.5`**, lints = `package:lints/recommended.yaml`. Run `dart analyze` before declaring a change done.
