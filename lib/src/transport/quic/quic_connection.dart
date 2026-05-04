// QUIC connection abstraction.
//
// A [QuicConnection] is the contract that application protocols
// (HTTP/3, WebTransport, XMPP, media, SIP) program against. It is
// transport-agnostic: implementations may wrap the demo server
// session, the demo client session, or a future production engine.
//
// The interface is intentionally minimal — only what application
// protocols need: ALPN, bidirectional streams, unidirectional
// streams, and unreliable datagrams.

import 'dart:async';
import 'dart:typed_data';

/// A QUIC stream (uni- or bidirectional).
abstract class QuicStream {
  /// QUIC-assigned stream id.
  int get id;

  /// True if the local side may send.
  bool get writable;

  /// True if the remote side may send (i.e. we may read).
  bool get readable;

  /// Inbound stream data, in order, after reassembly.
  Stream<Uint8List> get incoming;

  /// Append data to the stream.
  void write(Uint8List data, {bool fin = false});

  /// Close the local side (sends FIN if not already sent).
  Future<void> close();

  /// Abruptly cancel this stream (RESET_STREAM / STOP_SENDING).
  Future<void> reset({int errorCode = 0});
}

/// A QUIC connection.
abstract class QuicConnection {
  /// Negotiated ALPN value (e.g. `h3`, `webtransport`, `xmpp-quic`).
  String get alpn;

  /// Peer-chosen connection identifier.
  Uint8List get peerCid;

  /// Future that completes once the handshake is done and 1-RTT keys
  /// are installed.
  Future<void> get ready;

  /// Future that completes when the connection is fully closed.
  Future<void> get closed;

  /// Open a new bidirectional stream.
  Future<QuicStream> openBidirectionalStream();

  /// Open a new unidirectional stream.
  Future<QuicStream> openUnidirectionalStream();

  /// Streams initiated by the peer.
  Stream<QuicStream> get incomingStreams;

  /// Send an unreliable datagram (RFC 9221).
  void sendDatagram(Uint8List data);

  /// Inbound unreliable datagrams.
  Stream<Uint8List> get datagrams;

  /// Close the connection with an optional application error code.
  Future<void> close({int errorCode = 0, String? reason});
}
