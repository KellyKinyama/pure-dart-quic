// End-to-end integration tests for Socket.IO-over-WebTransport.

import 'dart:async';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 60));

void main() {
  SocketIoServer? server;
  late int port;
  var nextPort = 14860;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  Future<SocketIoServer> startServer() async {
    final s = SocketIoServer();
    await s.bind('127.0.0.1', port);
    server = s;
    return s;
  }

  test('emit + ack round-trips between client and server', () async {
    final s = await startServer();
    s.of('/').connections.listen((sock) {
      sock.on('ping', (args, [ack]) {
        expect(args, equals(<dynamic>['hello']));
        ack?.send(<dynamic>['pong', sock.id]);
      });
    });

    final client = await SocketIoClient.connect(host: '127.0.0.1', port: port);
    addTearDown(client.disconnect);

    final reply = await client
        .emitWithAck('ping', <dynamic>['hello'])
        .timeout(const Duration(seconds: 10));
    expect(reply.length, 2);
    expect(reply[0], 'pong');
    expect(reply[1], startsWith('sid-'));
  }, timeout: _to);

  test('server broadcast reaches every client', () async {
    final s = await startServer();
    s.of('/').connections.listen((sock) {
      sock.on('shout', (args, [_]) {
        s.of('/').emit('echo', args);
      });
    });

    final c1 = await SocketIoClient.connect(host: '127.0.0.1', port: port);
    final c2 = await SocketIoClient.connect(host: '127.0.0.1', port: port);
    final c3 = await SocketIoClient.connect(host: '127.0.0.1', port: port);
    addTearDown(c1.disconnect);
    addTearDown(c2.disconnect);
    addTearDown(c3.disconnect);

    final got = <Completer<List<dynamic>>>[
      Completer<List<dynamic>>(),
      Completer<List<dynamic>>(),
      Completer<List<dynamic>>(),
    ];
    c1.on('echo', (a, [_]) => got[0].complete(a));
    c2.on('echo', (a, [_]) => got[1].complete(a));
    c3.on('echo', (a, [_]) => got[2].complete(a));

    // Wait briefly for all 3 sockets to register on the server.
    await Future<void>.delayed(const Duration(milliseconds: 200));
    expect(s.of('/').sockets.length, 3);

    c1.emit('shout', <dynamic>['hi everyone']);

    final replies = await Future.wait(
      got.map((c) => c.future),
    ).timeout(const Duration(seconds: 10));
    for (final r in replies) {
      expect(r, equals(<dynamic>['hi everyone']));
    }
  }, timeout: _to);

  test('rooms scope broadcasts to joined sockets only', () async {
    final s = await startServer();
    s.of('/').connections.listen((sock) {
      sock.on('join', (args, [_]) => sock.join(args.first as String));
      sock.on('say', (args, [_]) {
        // Broadcast to the room (excluding sender).
        sock.to(args.first as String).emit('msg', <dynamic>[args.last]);
      });
    });

    final cA = await SocketIoClient.connect(host: '127.0.0.1', port: port);
    final cB = await SocketIoClient.connect(host: '127.0.0.1', port: port);
    final cC = await SocketIoClient.connect(host: '127.0.0.1', port: port);
    addTearDown(cA.disconnect);
    addTearDown(cB.disconnect);
    addTearDown(cC.disconnect);

    final aGot = <List<dynamic>>[];
    final bGot = <List<dynamic>>[];
    final cGot = <List<dynamic>>[];
    cA.on('msg', (a, [_]) => aGot.add(a));
    cB.on('msg', (a, [_]) => bGot.add(a));
    cC.on('msg', (a, [_]) => cGot.add(a));

    // A and B join "room1"; C stays out.
    cA.emit('join', <dynamic>['room1']);
    cB.emit('join', <dynamic>['room1']);
    await Future<void>.delayed(const Duration(milliseconds: 200));
    expect(s.of('/').socketsIn('room1').length, 2);

    // A says into room1 -> only B should get it (sender excluded, C not in).
    cA.emit('say', <dynamic>['room1', 'secret']);

    await Future<void>.delayed(const Duration(milliseconds: 500));

    expect(aGot, isEmpty);
    expect(
      bGot,
      equals(<List<dynamic>>[
        <dynamic>['secret'],
      ]),
    );
    expect(cGot, isEmpty);
  }, timeout: _to);

  test('namespaces isolate sockets', () async {
    final s = await startServer();
    s.of('/chat').connections.listen((sock) {
      sock.on('msg', (a, [_]) => s.of('/chat').emit('msg', a));
    });
    s.of('/news').connections.listen((sock) {
      sock.on('msg', (a, [_]) => s.of('/news').emit('msg', a));
    });

    final chat = await SocketIoClient.connect(
      host: '127.0.0.1',
      port: port,
      namespace: '/chat',
    );
    final news = await SocketIoClient.connect(
      host: '127.0.0.1',
      port: port,
      namespace: '/news',
    );
    addTearDown(chat.disconnect);
    addTearDown(news.disconnect);

    final chatGot = Completer<List<dynamic>>();
    final newsGot = <List<dynamic>>[];
    chat.on('msg', (a, [_]) {
      if (!chatGot.isCompleted) chatGot.complete(a);
    });
    news.on('msg', (a, [_]) => newsGot.add(a));

    await Future<void>.delayed(const Duration(milliseconds: 200));
    chat.emit('msg', <dynamic>['from-chat']);

    final got = await chatGot.future.timeout(const Duration(seconds: 10));
    expect(got, equals(<dynamic>['from-chat']));

    await Future<void>.delayed(const Duration(milliseconds: 200));
    expect(newsGot, isEmpty); // /news didn't see /chat traffic
  }, timeout: _to);

  test(
    'one server, many clients: chat-room fan-out + per-client ack',
    () async {
      const clientCount = 5;
      const room = 'lobby';
      final s = await startServer();

      // Server side: every connected socket auto-joins the lobby and
      // re-broadcasts incoming "say" messages to everyone *else* in the
      // room (sender excluded). Also answers a "whoami" event with an
      // ack carrying the socket id.
      s.of('/').connections.listen((sock) {
        sock.join(room);
        sock.on('say', (args, [_]) {
          sock.to(room).emit('msg', <dynamic>[sock.id, ...args]);
        });
        sock.on('whoami', (args, [ack]) {
          ack?.send(<dynamic>[sock.id]);
        });
      });

      // Connect N clients in parallel.
      final clients = await Future.wait(
        List<Future<SocketIoClient>>.generate(
          clientCount,
          (_) => SocketIoClient.connect(host: '127.0.0.1', port: port),
        ),
      );
      for (final c in clients) {
        addTearDown(c.disconnect);
      }

      // Per-client inbox + a Completer that fires once it has received
      // (clientCount - 1) messages — every other client's broadcast.
      final inboxes = List<List<List<dynamic>>>.generate(
        clientCount,
        (_) => <List<dynamic>>[],
      );
      final dones = List<Completer<void>>.generate(
        clientCount,
        (_) => Completer<void>(),
      );
      for (var i = 0; i < clientCount; i++) {
        final idx = i;
        clients[idx].on('msg', (a, [_]) {
          inboxes[idx].add(a);
          if (inboxes[idx].length >= clientCount - 1 &&
              !dones[idx].isCompleted) {
            dones[idx].complete();
          }
        });
      }

      // Wait for the server to register every socket in the lobby.
      await Future<void>.delayed(const Duration(milliseconds: 300));
      expect(s.of('/').sockets.length, clientCount);
      expect(s.of('/').socketsIn(room).length, clientCount);

      // Each client asks the server for its own assigned id via ack.
      final ids = await Future.wait<List<dynamic>>(
        clients.map((c) => c.emitWithAck('whoami')),
      ).timeout(const Duration(seconds: 10));
      final myIds = ids.map((r) => r.first as String).toList();
      expect(myIds.toSet().length, clientCount); // all unique
      for (final id in myIds) {
        expect(id, startsWith('sid-'));
      }

      // Every client shouts something into the room.
      for (var i = 0; i < clientCount; i++) {
        clients[i].emit('say', <dynamic>['hello-from-$i']);
      }

      // Wait until every client received (N - 1) messages.
      await Future.wait(
        dones.map((d) => d.future),
      ).timeout(const Duration(seconds: 15));

      for (var i = 0; i < clientCount; i++) {
        // Sender excluded -> nobody saw their own message.
        for (final m in inboxes[i]) {
          expect(
            m.first,
            isNot(myIds[i]),
            reason: 'client $i should not receive its own broadcast',
          );
        }
        // Should have heard from every other client exactly once.
        final senders = inboxes[i].map((m) => m.first as String).toSet();
        final expected = <String>{
          for (var j = 0; j < clientCount; j++)
            if (j != i) myIds[j],
        };
        expect(
          senders,
          equals(expected),
          reason: 'client $i missed/duplicated a sender',
        );
        // Payload sanity.
        for (final m in inboxes[i]) {
          final senderIdx = myIds.indexOf(m.first as String);
          expect(m.last, equals('hello-from-$senderIdx'));
        }
      }
    },
    timeout: _to,
  );
}
