// HTTP/3 reverse proxy CLI.
//
// Fronts an Apache (or any HTTP/1.1 / HTTP/2) origin with QUIC + HTTP/3.
//
// Usage:
//   dart run bin/http3_reverse_proxy.dart \
//       [--bind=127.0.0.1] [--port=4433] \
//       [--target=http://127.0.0.1:80] \
//       [--h2c] [--insecure] [--via=pure-dart-quic]
//
// Or positional (back-compat with earlier docs):
//   dart run bin/http3_reverse_proxy.dart 127.0.0.1 4433 http://127.0.0.1:80
//
// Examples — fronting Apache:
//
//   # Plain Apache on port 80 → expose as HTTP/3 on UDP 443.
//   dart run bin/http3_reverse_proxy.dart \
//       --bind=0.0.0.0 --port=443 --target=http://127.0.0.1:80
//
//   # Apache on https://internal:443 with self-signed cert → use --insecure.
//   dart run bin/http3_reverse_proxy.dart \
//       --target=https://internal --insecure
//
//   # Apache built with mod_http2 in h2c mode (rare but supported).
//   dart run bin/http3_reverse_proxy.dart \
//       --target=http://127.0.0.1:80 --h2c

import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final opts = _parse(args);

  final proxy = Http3ReverseProxy(
    target: opts.target,
    allowH2c: opts.h2c,
    allowInsecureUpstreamCertificates: opts.insecure,
    viaPseudonym: opts.via,
  );
  await proxy.bind(opts.bind, opts.port);

  stdout.writeln(
    'http3 reverse proxy listening on udp ${opts.bind}:${opts.port}',
  );
  stdout.writeln('  target            : ${opts.target}');
  stdout.writeln(
    '  upstream protocol : '
    '${opts.target.scheme == 'https' ? 'h2/http1.1 (ALPN)' : (opts.h2c ? 'h2c' : 'http/1.1')}',
  );
  stdout.writeln('  insecure TLS      : ${opts.insecure}');
  stdout.writeln('  Via pseudonym     : ${opts.via}');
  stdout.writeln('press Ctrl+C to stop.');

  ProcessSignal.sigint.watch().listen((_) async {
    stdout.writeln('shutting down…');
    await proxy.close();
    exit(0);
  });
}

class _Opts {
  final String bind;
  final int port;
  final Uri target;
  final bool h2c;
  final bool insecure;
  final String via;
  _Opts({
    required this.bind,
    required this.port,
    required this.target,
    required this.h2c,
    required this.insecure,
    required this.via,
  });
}

_Opts _parse(List<String> args) {
  var bind = '127.0.0.1';
  var port = 4433;
  var targetStr = 'http://127.0.0.1:80';
  var h2c = false;
  var insecure = false;
  var via = 'pure-dart-quic';

  final positional = <String>[];
  for (final a in args) {
    if (a == '-h' || a == '--help') {
      stdout.writeln(
        'Usage: dart run bin/http3_reverse_proxy.dart \\\n'
        '         [--bind=ADDR] [--port=N] [--target=URI] \\\n'
        '         [--h2c] [--insecure] [--via=NAME]',
      );
      exit(0);
    }
    if (a.startsWith('--bind=')) {
      bind = a.substring('--bind='.length);
    } else if (a.startsWith('--port=')) {
      port = int.parse(a.substring('--port='.length));
    } else if (a.startsWith('--target=')) {
      targetStr = a.substring('--target='.length);
    } else if (a == '--h2c') {
      h2c = true;
    } else if (a == '--insecure') {
      insecure = true;
    } else if (a.startsWith('--via=')) {
      via = a.substring('--via='.length);
    } else {
      positional.add(a);
    }
  }
  // Back-compat positional [bind] [port] [target].
  if (positional.isNotEmpty) bind = positional[0];
  if (positional.length > 1) port = int.parse(positional[1]);
  if (positional.length > 2) targetStr = positional[2];

  return _Opts(
    bind: bind,
    port: port,
    target: Uri.parse(targetStr),
    h2c: h2c,
    insecure: insecure,
    via: via,
  );
}
