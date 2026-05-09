// Tiny HTTP/1 origin used only by manual end-to-end tests of the
// HTTP/3 reverse proxy. Not part of the published surface.
import 'dart:io';

Future<void> main(List<String> args) async {
  final port = args.isNotEmpty ? int.parse(args.first) : 18080;
  final s = await HttpServer.bind(InternetAddress.loopbackIPv4, port);
  // ignore: avoid_print
  print('origin :${s.port}');
  s.listen((r) {
    final host = r.headers.value('host') ?? '';
    final fwd = r.headers.value('x-forwarded-for') ?? '';
    final via = r.headers.value('via') ?? '';
    r.response
      ..statusCode = 200
      ..headers.contentType = ContentType.text
      ..write(
        'hello from origin path=${r.uri.path} host=$host '
        'fwd=$fwd via=$via',
      )
      ..close();
  });
}
