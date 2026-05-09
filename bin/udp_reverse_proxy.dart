// UDP-over-QUIC reverse proxy CLI.
//
// Usage:
//   dart run bin/udp_reverse_proxy.dart [bind] [port] [target-host] [target-port]
//
// Defaults:
//   bind        = 127.0.0.1
//   port        = 4434
//   target-host = 127.0.0.1
//   target-port = 5353

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final bind = args.isNotEmpty ? args[0] : '127.0.0.1';
  final port = args.length > 1 ? int.parse(args[1]) : 4434;
  final tgtHost = args.length > 2 ? args[2] : '127.0.0.1';
  final tgtPort = args.length > 3 ? int.parse(args[3]) : 5353;

  final proxy = UdpReverseProxy(
    address: InternetAddress(tgtHost),
    port: tgtPort,
  );
  await proxy.bind(bind, port);

  print('udp reverse proxy: quic udp $bind:$port  ->  udp $tgtHost:$tgtPort');

  ProcessSignal.sigint.watch().listen((_) async {
    print('shutting down...');
    await proxy.close();
    exit(0);
  });
}
