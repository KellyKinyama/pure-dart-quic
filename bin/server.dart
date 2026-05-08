// Modular QUIC server entry point.
//
// Demonstrates: UDP -> QUIC -> {HTTP/3, WebTransport} via ALPN.
//
// This entry point implements a minimal "XoQ" (XMPP-style stanzas
// over WebTransport) chat server compatible with the bundled `app.js`
// browser client:
//
//   * Inbound WebTransport DATAGRAMs carry presence stanzas.
//   * Inbound WT unidirectional streams carry message stanzas.
//   * Inbound WT bidirectional streams carry IQ requests; the server
//     writes the response back on the same bidi stream and FINs.
//   * On session open the server sends a roster_update via a server-
//     initiated unidirectional stream.
//
// Single-user demo: the server reflects the connected user back as
// "User 2" so the UI shows roster, typing indicators, and echoed
// messages without needing a second client.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';

Future<void> main(List<String> args) async {
  final alpns = AlpnRegistry()
    ..register(Http3ProtocolFactory())
    ..register(WebTransportProtocolFactory());

  final endpoint = await QuicServerEndpoint.bind(
    address: InternetAddress('127.0.0.1'),
    port: 4433,
    alpns: alpns,
  );

  print(
    'modular server listening on ${endpoint.udp.address.address}:'
    '${endpoint.udp.port}  alpns=${alpns.advertisedAlpns}',
  );

  endpoint.connections.listen((conn) {
    print('accepted QUIC connection (alpn=${conn.alpn})');
    final proto = endpoint.protocol;
    if (proto is Http3ServerProtocol) {
      proto.webTransportSessions.listen(_handleWtSession);
    }
    conn.ready.then((_) => print('handshake complete'));
  });
}

// ---------------------------------------------------------------------
// XoQ chat server: routes message / iq / presence stanzas.
// ---------------------------------------------------------------------

const int _selfId = 1;
const int _peerId = 2;

void _handleWtSession(WebTransportSession wt) {
  print('▶ wt session opened: id=${wt.sessionId}');

  // Push an initial roster update so the client populates its peers
  // list as soon as `transport.ready` resolves.
  scheduleMicrotask(() async {
    try {
      final roster = jsonEncode(<String, dynamic>{
        'type': 'iq',
        'data': <String, dynamic>{
          'action': 'roster_update',
          'payload': jsonEncode(<int>[_selfId, _peerId]),
        },
      });
      final s = await wt.openUnidirectionalStream();
      s.write(_utf8(roster), fin: true);
      print('▶ pushed roster_update to session=${wt.sessionId}');
    } catch (e) {
      print('🛑 roster push failed: $e');
    }
  });

  // Presence / typing — broadcast back as if from the peer user.
  wt.datagrams.listen((data) {
    final stanza = _decodeStanza(data);
    print('◀ datagram session=${wt.sessionId}: $stanza');
    if (stanza == null) return;
    if (stanza['type'] == 'presence') {
      final dataMap = (stanza['data'] as Map?)?.cast<String, dynamic>();
      final reflected = <String, dynamic>{
        'type': 'presence',
        'data': <String, dynamic>{
          'from': _peerId,
          'status': dataMap?['status'] ?? 'online',
        },
      };
      wt.sendDatagram(_utf8(jsonEncode(reflected)));
    }
  });

  // Messages — accept on uni stream, echo back on a fresh server-
  // initiated uni stream so the UI sees it as an incoming peer message.
  wt.incomingUnidirectionalStreams.listen((peer) {
    _drain(peer).then((bytes) async {
      final stanza = _decodeStanza(bytes);
      print('◀ uni stream ${peer.streamId}: $stanza');
      if (stanza == null) return;
      if (stanza['type'] == 'message') {
        final inData =
            (stanza['data'] as Map?)?.cast<String, dynamic>() ??
            <String, dynamic>{};
        final reply = <String, dynamic>{
          'type': 'message',
          'data': <String, dynamic>{
            'id': inData['id'],
            'from': _peerId,
            'to': inData['from'] ?? _selfId,
            'body': '(echo) ${inData['body'] ?? ''}',
          },
        };
        final out = await wt.openUnidirectionalStream();
        out.write(_utf8(jsonEncode(reply)), fin: true);
      }
    });
  });

  // IQ requests — reply on the same bidi stream.
  wt.incomingBidirectionalStreams.listen((peer) {
    _drain(peer).then((bytes) {
      final stanza = _decodeStanza(bytes);
      print('◀ bidi stream ${peer.streamId}: $stanza');
      Map<String, dynamic> response;
      if (stanza != null && stanza['type'] == 'iq') {
        final inData =
            (stanza['data'] as Map?)?.cast<String, dynamic>() ??
            <String, dynamic>{};
        final action = inData['action'] as String?;
        if (action == 'sync_history') {
          final history = <String>[
            'User $_peerId: hi from the silo',
            'User $_selfId: hello world',
            'User $_peerId: welcome to XoQ',
          ];
          response = <String, dynamic>{
            'type': 'iq',
            'data': <String, dynamic>{
              'id': inData['id'],
              'msg': 'History Loaded',
              'payload': jsonEncode(history),
            },
          };
        } else {
          response = <String, dynamic>{
            'type': 'iq',
            'data': <String, dynamic>{
              'id': inData['id'],
              'msg': 'Unknown Action',
              'payload': jsonEncode(<String>[]),
            },
          };
        }
      } else {
        response = <String, dynamic>{
          'type': 'iq',
          'data': <String, dynamic>{'msg': 'Bad Request', 'payload': '{}'},
        };
      }
      peer.write(_utf8(jsonEncode(response)), fin: true);
    });
  });
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

Uint8List _utf8(String s) => Uint8List.fromList(utf8.encode(s));

Future<Uint8List> _drain(WebTransportStream s) {
  final c = Completer<Uint8List>();
  final buf = BytesBuilder();
  s.incoming.listen(
    buf.add,
    onDone: () => c.complete(buf.toBytes()),
    onError: c.completeError,
    cancelOnError: true,
  );
  return c.future;
}

Map<String, dynamic>? _decodeStanza(Uint8List bytes) {
  try {
    final s = utf8.decode(bytes);
    final v = jsonDecode(s);
    if (v is Map<String, dynamic>) return v;
    return null;
  } catch (_) {
    return null;
  }
}
