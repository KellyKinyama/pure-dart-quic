// HTTP/3 reverse proxy CLI.
//
// Usage:
//   dart run bin/http3_reverse_proxy.dart [bind] [port] [target]
//
// Defaults:
//   bind   = 127.0.0.1
//   port   = 4433
//   target = http://127.0.0.1:8080
//
// All inbound HTTP/3 requests are forwarded to [target] over plain
// HTTP/1.1 (dart:io HttpClient) and the response is streamed back
// over HTTP/3.

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final bind = args.isNotEmpty ? args[0] : '127.0.0.1';
  final port = args.length > 1 ? int.parse(args[1]) : 4433;
  final target = Uri.parse(args.length > 2 ? args[2] : 'http://127.0.0.1:8080');

  final proxy = Http3ReverseProxy(target: target);
  await proxy.bind(bind, port);

  print('http3 reverse proxy: udp $bind:$port  ->  $target');

  ProcessSignal.sigint.watch().listen((_) async {
    print('shutting down...');
    await proxy.close();
    exit(0);
  });
}
