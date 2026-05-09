// QUIC → TCP reverse proxy CLI.
//
// Usage:
//   dart run bin/tcp_reverse_proxy.dart [bind] [port] [target-host] [target-port]
//
// Defaults: 127.0.0.1 4439 127.0.0.1 22

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final bind = args.isNotEmpty ? args[0] : '127.0.0.1';
  final port = args.length > 1 ? int.parse(args[1]) : 4439;
  final targetHost = args.length > 2 ? args[2] : '127.0.0.1';
  final targetPort = args.length > 3 ? int.parse(args[3]) : 22;

  final proxy = TcpReverseProxy(
    address: InternetAddress(targetHost),
    port: targetPort,
  );
  await proxy.bind(InternetAddress(bind), port);
  print(
    'tcp-over-quic proxy: $bind:$port  ALPN=tcp-proxy  '
    '→ tcp://$targetHost:$targetPort',
  );

  ProcessSignal.sigint.watch().listen((_) async {
    print('shutting down…');
    await proxy.close();
    exit(0);
  });
}
