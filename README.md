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


## Server example
The following example shows a minimal QUIC server implemented using this library.
It listens on UDP, creates a QuicServerSession, and forwards received QUIC packets into the session.
This server supports:

QUIC handshake
TLS 1.3 over QUIC
HTTP/3 control stream bootstrap
WebTransport CONNECT
WebTransport DATAGRAM echo

Example: simple QUIC server

```dart
import 'dart:io';

import '../../constants.dart';
import 'quic_server_session.dart';

// import '../constants.dart';
// import 'constants.dart';
// import 'quic_server_session3.dart';

Future<void> main() async {
  final socket = await RawDatagramSocket.bind("127.0.0.1", 4433);

  QuicServerSession quicSession = QuicServerSession(socket: socket);

  print("server listening ip:${socket.address.address}:${socket.port}");
  bool peerSet = false;

  socket.listen((ev) {
    if (ev == RawSocketEvent.read) {
      final dg = socket.receive();
      if (dg == null) return;

      print("Data datagram received: ${dg.data.length}");

      // ✅ Create session on first packet only
      // quicSession ??= QuicServerSession(
      //   socket: socket,
      //   // peerAddress: dg.address,
      //   // peerPort: dg.port,
      //   // ✅ NO prebuilt flight injected
      // );
      if (!peerSet) {
        quicSession.peerAddress = dg.address;
        quicSession.peerPort = dg.port;
        peerSet = true;
      }

      final packetList = splitCoalescedPackets(dg.data);
      print(packetList.length);

      for (final pkt in packetList) {
        quicSession.handleDatagram(pkt);
      }
    }
  });
}

```
How it works

A UDP socket is created using RawDatagramSocket
A single QuicServerSession instance manages:

connection IDs
packet number spaces
TLS handshake state
HTTP/3 and WebTransport processing


Incoming UDP datagrams are:

split into individual QUIC packets
forwarded to handleDatagram()


The server automatically:

completes the QUIC + TLS handshake
sends HANDSHAKE_DONE
opens the HTTP/3 control stream
enables WebTransport



Notes

This is a single-connection demo server
Intended for experimentation, learning, and protocol research
Production features such as:

congestion control
connection migration
stateless retry
certificate lifecycle management
are not implemented


```dart
import 'dart:async';
// import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:hex/hex.dart';

// import '../constants.dart';
import '../../constants.dart';
import 'quic_session3.dart';

Future<void> main() async {
  final socket = await RawDatagramSocket.bind("127.0.0.1", 0);

  final quicSession = QuicSession(
    Uint8List.fromList(HEX.decode("0001020304050607")),
    socket,
  );
  print("listening ip:${socket.address.address}:${socket.port}");
  socket.listen((ev) {
    if (ev == RawSocketEvent.read) {
      final dg = socket.receive();
      if (dg != null) {
        // _onPacket(dg);
        print("Data datagram received: ${dg.data.length}");
        final packetList = splitCoalescedPackets(dg.data);
        print(packetList.length);
        for (final pkt in packetList) {
          _receivingQuicPacket(dg.address, dg.port, pkt);
          quicSession.handleQuicPacket(pkt);
        }
      }
    }
  });

  quicSession.sendClientHello(
    address: InternetAddress("127.0.0.1"),
    port: 4433,
    authority: 'localhost',
  );

  // Timer.periodic(Duration(seconds: 2), (_) {
  // socket.send(udp1ClientHello, InternetAddress("127.0.0.1"), 4433);
  // });
}

void _receivingQuicPacket(InternetAddress address, int port, Uint8List pkt) {}

final udp1ClientHello = Uint8List.fromList(
  HEX.decode(
    "cd 00 00 00 01 08 00 01 02 03 04 05 06 07 05 63 5f 63 69 64 00 41 03 98 1c 36 a7 ed 78 71 6b e9 71 1b a4 98 b7 ed 86 84 43 bb 2e 0c 51 4d 4d 84 8e ad cc 7a 00 d2 5c e9 f9 af a4 83 97 80 88 de 83 6b e6 8c 0b 32 a2 45 95 d7 81 3e a5 41 4a 91 99 32 9a 6d 9f 7f 76 0d d8 bb 24 9b f3 f5 3d 9a 77 fb b7 b3 95 b8 d6 6d 78 79 a5 1f e5 9e f9 60 1f 79 99 8e b3 56 8e 1f dc 78 9f 64 0a ca b3 85 8a 82 ef 29 30 fa 5c e1 4b 5b 9e a0 bd b2 9f 45 72 da 85 aa 3d ef 39 b7 ef af ff a0 74 b9 26 70 70 d5 0b 5d 07 84 2e 49 bb a3 bc 78 7f f2 95 d6 ae 3b 51 43 05 f1 02 af e5 a0 47 b3 fb 4c 99 eb 92 a2 74 d2 44 d6 04 92 c0 e2 e6 e2 12 ce f0 f9 e3 f6 2e fd 09 55 e7 1c 76 8a a6 bb 3c d8 0b bb 37 55 c8 b7 eb ee 32 71 2f 40 f2 24 51 19 48 70 21 b4 b8 4e 15 65 e3 ca 31 96 7a c8 60 4d 40 32 17 0d ec 28 0a ee fa 09 5d 08 b3 b7 24 1e f6 64 6a 6c 86 e5 c6 2c e0 8b e0 99"
        .replaceAll(" ", ""),
  ),
);

```