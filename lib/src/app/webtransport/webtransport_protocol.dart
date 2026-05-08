// WebTransport-over-HTTP/3 module.
//
// WebTransport is layered on HTTP/3 (extended CONNECT, RFC 8441 +
// draft-ietf-webtrans-http3) and shares its ALPN (`h3`). The protocol
// logic therefore lives in the HTTP/3 module under `../h3/`. This file
// exists to (a) re-export the public WebTransport types and (b)
// provide a factory that registers the same handler under the
// historical `wt` / `webtransport` ALPN strings if a server prefers
// to advertise them explicitly.

import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';
import '../h3/h3_protocol.dart';

export '../h3/h3_protocol.dart' show WebTransportSession;

class WebTransportProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const <String>['wt', 'webtransport'];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      Http3ServerProtocol(conn, conn.alpn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      Http3ClientProtocol(conn, alpn: conn.alpn);
}
