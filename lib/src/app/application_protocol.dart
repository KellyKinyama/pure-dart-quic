// Application-protocol interface (the "X over QUIC" plug point).
//
// Each protocol module — HTTP/3, WebTransport, XMPP, media, SIP —
// implements [ApplicationProtocolFactory]. The QUIC endpoint
// consults the [AlpnRegistry] to pick a factory based on the
// negotiated ALPN value.

import 'dart:async';

import '../transport/quic/quic_connection.dart';

/// The runtime instance of an application protocol bound to one
/// concrete [QuicConnection].
abstract class ApplicationProtocol {
  /// Negotiated ALPN string this instance was created for.
  String get alpn;

  /// Begin protocol-specific bootstrap (open control stream, send
  /// settings, etc.). Called once after the QUIC handshake completes.
  Future<void> start();

  /// Tear down protocol-specific state.
  Future<void> stop();
}

/// Factory that produces an [ApplicationProtocol] for a given QUIC
/// connection. Roles are kept separate because client/server bootstrap
/// usually differ (e.g. who opens the control stream).
abstract class ApplicationProtocolFactory {
  /// ALPN values this factory advertises / accepts.
  List<String> get alpnIds;

  ApplicationProtocol createServer(QuicConnection conn);
  ApplicationProtocol createClient(QuicConnection conn);
}
