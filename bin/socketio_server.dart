// Socket.IO-over-WebTransport demo server.
//
// Mirrors the JS Socket.IO API:
//   * everyone joins the "lobby" room on connect
//   * "say" events are re-broadcast to every other client in the lobby
//   * "whoami" event responds (via ack) with the caller's socket id
//   * "ping" event responds (via ack) with ['pong', <millis>]
//
// Pair with `examples/socketio/index.html` for a browser client.
//
// Run:
//   dart run bin/socketio_server.dart
//
// Then open the example HTML page (see examples/socketio/README.md
// for browser launch flags — WebTransport requires a trusted cert
// or `--ignore-certificate-errors-spki-list=...`).

import 'package:pure_dart_quic/pure_dart_quic.dart';

const int _port = 4444;
const String _room = 'lobby';

Future<void> main(List<String> args) async {
  final io = SocketIoServer();

  io.of('/').connections.listen((sock) {
    print('✅ socket connected id=${sock.id}');
    sock.join(_room);

    sock.on('say', (args, [_]) {
      // Re-broadcast to everyone else in the lobby.
      sock.to(_room).emit('msg', <dynamic>[sock.id, ...args]);
    });

    sock.on('whoami', (args, [ack]) {
      ack?.send(<dynamic>[sock.id]);
    });

    sock.on('ping', (args, [ack]) {
      ack?.send(<dynamic>['pong', DateTime.now().millisecondsSinceEpoch]);
    });

    sock.onDisconnect.listen((_) {
      print('🛑 socket disconnected id=${sock.id}');
    });
  });

  await io.bind('127.0.0.1', _port);
  print(
    'socket.io-over-webtransport listening on '
    '${io.address?.address}:${io.port}\n'
    '  WT path : /socket.io\n'
    '  events  : say <text>, whoami, ping',
  );
}
