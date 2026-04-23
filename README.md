# Pure Dart QUIC + HTTP/3 + WebTransport

A **pure Dart** implementation of:

- **QUIC transport**
- **TLS 1.3 over QUIC**
- **HTTP/3**
- **WebTransport**
- **WebTransport DATAGRAM**
- basic **QPACK / HTTP/3 SETTINGS** handling

This project demonstrates a full end-to-end QUIC stack written in Dart, including:

- Initial secret derivation
- QUIC packet protection / header protection
- TLS handshake message exchange over QUIC CRYPTO frames
- 1-RTT key installation
- HTTP/3 control stream bootstrap
- WebTransport `CONNECT`
- WebTransport datagram echo

---

## Status

### Implemented

- QUIC Initial / Handshake / 1-RTT packet protection
- Packet number spaces
- ACK generation and parsing
- CRYPTO frame reassembly
- TLS 1.3 handshake:
  - ClientHello
  - ServerHello
  - EncryptedExtensions
  - Certificate
  - CertificateVerify
  - Finished
- HTTP/3:
  - SETTINGS frame
  - control stream bootstrap
  - basic HEADERS / DATA framing
- QPACK:
  - static-table-based header encoding / decoding
- WebTransport:
  - Extended CONNECT
  - DATAGRAM frames
  - session establishment
  - datagram echo test
- Client bootstrap streams:
  - client control stream
  - client QPACK encoder stream
  - client QPACK decoder stream

---

## What this project proves

This implementation is not just a toy packet parser — it demonstrates a real protocol stack capable of:

- speaking QUIC over UDP
- negotiating TLS 1.3 inside QUIC CRYPTO frames
- deriving handshake and application secrets correctly
- speaking HTTP/3 on top of QUIC
- establishing a WebTransport session
- exchanging WebTransport datagrams

It has been tested successfully:

- against the included pure Dart server
- against stricter real HTTP/3 / WebTransport servers

---

## Project structure

A simplified view of the important pieces:

```text
lib/
├── buffer.dart
├── constants.dart
├── utils.dart
├── packet/
│   └── quic_packet.dart
├── frames/
│   └── quic_ack.dart
├── streams/
│   └── stream.dart
├── handshake/
│   ├── client_hello.dart
│   ├── server_hello.dart
│   └── tls_server_builder.dart
├── h3/
│   └── h3.dart
├── cipher/
│   ├── cert_utils.dart
│   ├── fingerprint.dart
│   ├── hash.dart
│   ├── hkdf.dart
│   └── x25519.dart
└── connection/
    ├── client/
    │   ├── client3.dart
    │   └── quic_session3.dart
    └── server/
        ├── server2.dart
        └── quic_server_session.dart
