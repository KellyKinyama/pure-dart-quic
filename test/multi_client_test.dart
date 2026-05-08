// Verifies that a single QuicServerEndpoint can host several concurrent
// QUIC clients, demuxed by UDP 4-tuple.

import 'dart:async';
import 'dart:io';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

const _to = Timeout(Duration(seconds: 60));

void main() {
  QuicServerEndpoint? server;
  late int port;
  var nextPort = 14830;

  setUp(() {
    port = nextPort++;
  });

  tearDown(() async {
    await server?.close();
    server = null;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  });

  test('two XMPP clients are served independently', () async {
    final alpns = AlpnRegistry()..register(XmppOverQuicProtocolFactory());
    server = await QuicServerEndpoint.bind(
      address: InternetAddress.loopbackIPv4,
      port: port,
      alpns: alpns,
    );

    final acceptedConns = <QuicConnection>[];
    server!.connections.listen((conn) async {
      acceptedConns.add(conn);
      final proto = server!.protocolFor(conn);
      if (proto is XmppOverQuicServerProtocol) {
        final xmpp = await proto.opened;
        // Tag each reply with an id so clients can distinguish their own
        // responses if any cross-talk leaks through.
        final myId = acceptedConns.length;
        xmpp.stanzas.listen((s) => xmpp.send('<echo id="$myId">$s</echo>'));
      }
    });

    Future<List<String>> dialAndChat(String tag) async {
      final clientAlpns = AlpnRegistry()
        ..register(XmppOverQuicProtocolFactory());
      final ep = await QuicClientEndpoint.connect(
        remoteAddress: InternetAddress.loopbackIPv4,
        remotePort: port,
        authority: 'localhost',
        alpns: clientAlpns,
        alpn: 'xmpp-quic',
      );
      addTearDown(ep.close);

      await ep.connection.ready.timeout(const Duration(seconds: 15));
      final proto = ep.protocol as XmppOverQuicClientProtocol;
      final xmpp = await proto.opened.timeout(const Duration(seconds: 15));

      final got = <String>[];
      final done = Completer<void>();
      xmpp.stanzas.listen((s) {
        got.add(s);
        if (got.length == 2) done.complete();
      });

      xmpp.send('<m>$tag-1</m>');
      xmpp.send('<m>$tag-2</m>');
      await done.future.timeout(const Duration(seconds: 15));
      return got;
    }

    final results = await Future.wait([
      dialAndChat('alice'),
      dialAndChat('bob'),
    ]);

    final aliceReplies = results[0];
    final bobReplies = results[1];

    // Each client got two replies.
    expect(aliceReplies, hasLength(2));
    expect(bobReplies, hasLength(2));

    // Each client only saw echoes of its own messages.
    expect(
      aliceReplies.every((s) => s.contains('alice')),
      isTrue,
      reason: 'alice saw cross-talk: $aliceReplies',
    );
    expect(
      bobReplies.every((s) => s.contains('bob')),
      isTrue,
      reason: 'bob saw cross-talk: $bobReplies',
    );

    // The server emitted exactly two distinct connection events.
    expect(acceptedConns, hasLength(2));
    expect(server!.activeConnections, hasLength(2));
  }, timeout: _to);

  test('idle peers are evicted from activeConnections', () async {
    final alpns = AlpnRegistry()..register(XmppOverQuicProtocolFactory());
    server = await QuicServerEndpoint.bind(
      address: InternetAddress.loopbackIPv4,
      port: port,
      alpns: alpns,
      idleTimeout: const Duration(seconds: 1),
    );

    server!.connections.listen((conn) async {
      final proto = server!.protocolFor(conn);
      if (proto is XmppOverQuicServerProtocol) {
        final xmpp = await proto.opened;
        xmpp.stanzas.listen((s) => xmpp.send('<echo>$s</echo>'));
      }
    });

    final clientAlpns = AlpnRegistry()..register(XmppOverQuicProtocolFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: InternetAddress.loopbackIPv4,
      remotePort: port,
      authority: 'localhost',
      alpns: clientAlpns,
      alpn: 'xmpp-quic',
    );
    await ep.connection.ready.timeout(const Duration(seconds: 15));
    final proto = ep.protocol as XmppOverQuicClientProtocol;
    final xmpp = await proto.opened.timeout(const Duration(seconds: 15));

    final reply = Completer<String>();
    xmpp.stanzas.listen((s) {
      if (!reply.isCompleted) reply.complete(s);
    });
    xmpp.send('<m>hello</m>');
    await reply.future.timeout(const Duration(seconds: 10));

    expect(server!.activeConnections, hasLength(1));

    // Tear the client down and let the server's idle sweep run.
    await ep.close();
    await Future<void>.delayed(const Duration(seconds: 3));

    expect(
      server!.activeConnections,
      isEmpty,
      reason: 'idle peer should have been evicted',
    );
  }, timeout: _to);
}
