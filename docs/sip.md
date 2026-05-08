# SIP-over-QUIC (stub)

ALPN: `sip` (provisional). Module: [`lib/src/app/sip/sip_protocol.dart`](../lib/src/app/sip/sip_protocol.dart).

This is a **registration-only stub**. The factory is wired into the
ALPN registry and the per-side classes implement `ApplicationProtocol`,
but no SIP framing is produced or parsed yet.

```dart
final alpns = AlpnRegistry()..register(SipOverQuicProtocolFactory());
```

## Intended design (TODO)

- Each SIP transaction maps to a unidirectional stream pair, **or** all
  SIP traffic muxes onto a single bidi control stream — both approaches
  are listed in `draft-hurst-sip-quic`.
- REGISTER / INVITE / OPTIONS would be sent as opaque message blobs on
  fresh streams.
- Re-use the QUIC connection's congestion state instead of running over
  TCP/TLS or raw UDP.

No demo binary ships for SIP yet. Contributions welcome.
