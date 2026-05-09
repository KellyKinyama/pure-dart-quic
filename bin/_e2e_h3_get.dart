// Tiny HTTP/3 client used only by manual end-to-end tests of the
// HTTP/3 reverse proxy. Not part of the published surface.
import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final port = args.isNotEmpty ? int.parse(args.first) : 14433;
  final path = args.length > 1 ? args[1] : '/hello';
  final alpns = AlpnRegistry()..register(Http3ClientProtocolFactory());
  final ep = await QuicClientEndpoint.connect(
    remoteAddress: InternetAddress.loopbackIPv4,
    remotePort: port,
    authority: 'localhost',
    alpns: alpns,
    alpn: 'h3',
  );
  final p = ep.protocol as Http3ClientProtocol;
  p.autoConnectWebTransport = false;
  await ep.connection.ready;
  final r = await p.get(path);
  // ignore: avoid_print
  print('H3 STATUS=${r.headers[':status']} BODY=${r.bodyAsString}');
  await ep.close();
  exit(0);
}
