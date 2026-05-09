/// Pure-Dart QUIC + TLS 1.3 + HTTP/3 + WebTransport.
///
/// Modular public API. Layout:
///
/// * `UdpTransport` — UDP socket abstraction
/// * `QuicConnection` / `QuicServerEndpoint` / `QuicClientEndpoint` —
///   QUIC transport layer
/// * `ApplicationProtocol` / `AlpnRegistry` — pluggable application
///   protocols selected via TLS ALPN
/// * Concrete protocol modules: HTTP/3, WebTransport, XMPP-over-QUIC
///   (stub), Media-over-QUIC (stub), SIP-over-QUIC (stub)
///
/// See `bin/server.dart` and `bin/client.dart` for end-to-end examples.
library;

export 'src/transport/udp/udp_transport.dart';
export 'src/transport/quic/quic_connection.dart';
export 'src/transport/quic/quic_endpoint.dart';
export 'src/transport/quic/server_connection.dart';
export 'src/transport/quic/client_connection.dart';
export 'src/transport/quic/engine_quic_stream.dart';
export 'src/transport/quic/recovery/recovery.dart';

export 'src/app/application_protocol.dart';
export 'src/app/alpn_registry.dart';
export 'src/app/h3/h3_protocol.dart';
export 'src/app/h3/http3_server.dart';
export 'src/app/h3/http3_reverse_proxy.dart';
export 'src/app/udp_proxy/udp_reverse_proxy.dart';
export 'src/app/udp_proxy/udp_proxy_client.dart';
export 'src/app/tcp_proxy/tcp_reverse_proxy.dart';
export 'src/app/tcp_proxy/tcp_proxy_client.dart';
export 'src/app/dns/dns_protocol.dart';
export 'src/app/redis/redis_protocol.dart';
export 'src/app/webtransport/webtransport_protocol.dart';
export 'src/app/xmpp/xmpp_protocol.dart';
export 'src/app/mqtt/mqtt_protocol.dart';
export 'src/app/media/media_protocol.dart';
export 'src/app/sip/sip_protocol.dart';
export 'src/app/webdav/webdav_protocol.dart';
export 'src/app/webdav/webdav_h3.dart';
export 'src/app/socketio/socketio_protocol.dart';

/// Legacy stub kept for the existing `test/pure_dart_quic_test.dart`.
int calculate() => 42;
