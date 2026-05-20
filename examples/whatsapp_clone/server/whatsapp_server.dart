// WhatsApp-clone server: XMPP-over-QUIC.
//
// Run from the repo root:
//   dart run examples/whatsapp_clone/server/whatsapp_server.dart
//
// Listens on UDP 0.0.0.0:4435, ALPN `xmpp-quic`. Multi-client.
// Implements a tiny XMPP-flavoured protocol with length-prefixed
// stanzas (handled by XmppOverQuicConnection):
//
//   <auth jid='alice@chat' name='Alice' avatar='...'/>
//   <auth-ok jid='...' ts='...'/>
//   <roster><contact jid='...' name='...' presence='online|offline'/>…</roster>
//   <presence from='jid' show='online|offline' ts='...'/>
//   <message id='m1' from='a' to='b' type='chat' ts='...'><body>hi</body></message>
//   <receipt id='m1' from='b' to='a' type='delivered|read'/>
//   <chatstate from='a' to='b' state='composing|paused|active'/>
//   <history with='b' limit='50'/>
//     -> <history-result with='b'>…<message …/>…</history-result>
//   <group-create id='g1' name='Family'><member jid='b'/>…</group-create>
//   <group-message id='m1' group='g1' from='a' ts='...'><body>…</body></group-message>
//
// Media is sent inside <body> as a small XML element:
//   <body><media type='image/png' name='pic.png'>BASE64</media></body>
// or plain text. The server doesn't inspect bodies.

import 'dart:async';
import 'dart:io';
import 'dart:convert';

import 'package:pure_dart_quic/pure_dart_quic.dart';

final Map<String, _Session> _online = <String, _Session>{};
final Map<String, List<String>> _offlineQueue = <String, List<String>>{};
final Map<String, List<_StoredMsg>> _history = <String, List<_StoredMsg>>{};
final Map<String, _Contact> _contacts = <String, _Contact>{};
final Map<String, _Group> _groups = <String, _Group>{};

class _Contact {
  final String jid;
  String name;
  String? avatar;
  DateTime lastSeen = DateTime.now();
  _Contact(this.jid, this.name, {this.avatar});
}

class _Group {
  final String id;
  String name;
  final Set<String> members = <String>{};
  _Group(this.id, this.name);
}

class _StoredMsg {
  final String stanza;
  final DateTime ts;
  _StoredMsg(this.stanza, this.ts);
}

class _Session {
  final String jid;
  final XmppOverQuicConnection xmpp;
  _Session(this.jid, this.xmpp);
}

String _esc(String s) => const HtmlEscape(HtmlEscapeMode.attribute).convert(s);
String _now() => DateTime.now().toUtc().toIso8601String();

String? _attr(String stanza, String name) {
  final m = RegExp(" $name='([^']*)'").firstMatch(stanza);
  return m?.group(1);
}

String _tag(String stanza) {
  final m = RegExp(r"<([A-Za-z\-]+)").firstMatch(stanza);
  return m?.group(1) ?? '';
}

String _historyKey(String a, String b) {
  final p = [a, b]..sort();
  return '${p[0]}|${p[1]}';
}

Future<void> main(List<String> args) async {
  final port = args.isNotEmpty ? int.parse(args[0]) : 4435;
  final alpns = AlpnRegistry()..register(XmppOverQuicProtocolFactory());

  final endpoint = await QuicServerEndpoint.bind(
    address: InternetAddress.anyIPv4,
    port: port,
    alpns: alpns,
  );

  print(
    '[whatsapp-server] listening udp ${endpoint.udp.address.address}:'
    '${endpoint.udp.port}  alpns=${alpns.advertisedAlpns}',
  );

  endpoint.connections.listen((conn) {
    print('[server] new QUIC conn alpn=${conn.alpn}');
    final proto = endpoint.protocolFor(conn);
    if (proto is XmppOverQuicServerProtocol) {
      proto.opened.then((xmpp) => _handleClient(xmpp));
    }
  });
}

void _handleClient(XmppOverQuicConnection xmpp) {
  String? jid;
  print('[server] xmpp stream bound');

  xmpp.stanzas.listen(
    (raw) {
      try {
        _onStanza(xmpp, raw, (j) => jid = j, () => jid);
      } catch (e, st) {
        print('[server] stanza error: $e\n$st');
      }
    },
    onDone: () {
      final j = jid;
      if (j != null) {
        print('[server] $j disconnected');
        _online.remove(j);
        _broadcastPresence(j, 'offline');
        _contacts[j]?.lastSeen = DateTime.now();
      }
    },
  );
}

void _onStanza(
  XmppOverQuicConnection xmpp,
  String raw,
  void Function(String) setJid,
  String? Function() getJid,
) {
  final tag = _tag(raw);
  switch (tag) {
    case 'auth':
      final j = _attr(raw, 'jid') ?? 'anon@chat';
      final name = _attr(raw, 'name') ?? j.split('@').first;
      final avatar = _attr(raw, 'avatar');
      setJid(j);
      _contacts.putIfAbsent(j, () => _Contact(j, name, avatar: avatar));
      _contacts[j]!
        ..name = name
        ..avatar = avatar
        ..lastSeen = DateTime.now();
      _online[j] = _Session(j, xmpp);
      print('[server] auth $j ($name) online=${_online.length}');

      xmpp.send("<auth-ok jid='${_esc(j)}' ts='${_now()}'/>");
      _sendRoster(xmpp, j);
      _flushOffline(xmpp, j);
      _broadcastPresence(j, 'online');
      break;

    case 'presence':
      final j = getJid();
      if (j == null) return;
      final show = _attr(raw, 'show') ?? 'online';
      _broadcastPresence(j, show);
      break;

    case 'message':
      final from = getJid();
      final to = _attr(raw, 'to');
      if (from == null || to == null) return;
      final stamped = _stamp(raw, from);
      _history
          .putIfAbsent(_historyKey(from, to), () => <_StoredMsg>[])
          .add(_StoredMsg(stamped, DateTime.now()));
      final target = _online[to];
      if (target != null) {
        target.xmpp.send(stamped);
      } else {
        _offlineQueue.putIfAbsent(to, () => <String>[]).add(stamped);
      }
      // Auto delivery receipt back to sender.
      final mid = _attr(raw, 'id') ?? '';
      xmpp.send(
        "<receipt id='${_esc(mid)}' from='${_esc(to)}' "
        "to='${_esc(from)}' type='delivered'/>",
      );
      break;

    case 'receipt':
      final to = _attr(raw, 'to');
      if (to == null) return;
      final target = _online[to];
      if (target != null) target.xmpp.send(raw);
      break;

    case 'chatstate':
      final to = _attr(raw, 'to');
      if (to == null) return;
      final target = _online[to];
      if (target != null) target.xmpp.send(raw);
      break;

    // Call signaling — server is a pure relay.
    case 'call-offer':
    case 'call-answer':
    case 'call-ice':
    case 'call-end':
    case 'call-reject':
    case 'call-cancel':
      {
        final to = _attr(raw, 'to');
        final from = getJid();
        if (to == null || from == null) break;
        final stamped = _stamp(raw, from);
        final target = _online[to];
        if (target != null) {
          target.xmpp.send(stamped);
        } else if (tag == 'call-offer') {
          // Peer is offline -> immediately bounce a reject so the
          // caller's UI tears down.
          final id = _attr(raw, 'id') ?? '';
          xmpp.send(
            "<call-reject id='${_esc(id)}' from='${_esc(to)}' "
            "to='${_esc(from)}' reason='offline'/>",
          );
        }
      }
      break;

    case 'history':
      final me = getJid();
      final peer = _attr(raw, 'with');
      if (me == null || peer == null) return;
      final list = _history[_historyKey(me, peer)] ?? const <_StoredMsg>[];
      final buf = StringBuffer("<history-result with='${_esc(peer)}'>");
      for (final m in list) {
        buf.write(m.stanza);
      }
      buf.write('</history-result>');
      xmpp.send(buf.toString());
      break;

    case 'group-create':
      final gid = _attr(raw, 'id') ?? 'g${_groups.length + 1}';
      final name = _attr(raw, 'name') ?? gid;
      final me = getJid();
      final g = _groups.putIfAbsent(gid, () => _Group(gid, name))..name = name;
      if (me != null) g.members.add(me);
      for (final m in RegExp(r"<member jid='([^']+)'/>").allMatches(raw)) {
        g.members.add(m.group(1)!);
      }
      for (final j in g.members) {
        final s = _online[j];
        if (s != null) {
          final mbuf = StringBuffer(
            "<group-info id='${_esc(gid)}' name='${_esc(name)}'>",
          );
          for (final mem in g.members) {
            mbuf.write("<member jid='${_esc(mem)}'/>");
          }
          mbuf.write('</group-info>');
          s.xmpp.send(mbuf.toString());
        }
      }
      break;

    case 'group-message':
      final gid = _attr(raw, 'group');
      if (gid == null) return;
      final g = _groups[gid];
      if (g == null) return;
      final from = getJid();
      final stamped = _stamp(raw, from ?? '?');
      final key = 'g:$gid';
      _history
          .putIfAbsent(key, () => <_StoredMsg>[])
          .add(_StoredMsg(stamped, DateTime.now()));
      for (final m in g.members) {
        if (m == from) continue;
        final s = _online[m];
        if (s != null) {
          s.xmpp.send(stamped);
        } else {
          _offlineQueue.putIfAbsent(m, () => <String>[]).add(stamped);
        }
      }
      break;

    default:
      // Ignore unknown stanzas.
      break;
  }
}

String _stamp(String stanza, String from) {
  // Inject from/ts attributes if missing. Cheap string surgery.
  var s = stanza;
  if (!s.contains(" from='")) {
    s = s
        .replaceFirst('<', "<")
        .replaceFirst(RegExp(r'^<([A-Za-z\-]+)'), "<\$1 from='${_esc(from)}'");
  }
  if (!s.contains(" ts='")) {
    s = s.replaceFirst(
      RegExp(r'^<([A-Za-z\-]+)([^>]*)'),
      "<\$1\$2 ts='${_now()}'",
    );
  }
  return s;
}

void _sendRoster(XmppOverQuicConnection xmpp, String me) {
  final buf = StringBuffer('<roster>');
  for (final c in _contacts.values) {
    if (c.jid == me) continue;
    final presence = _online.containsKey(c.jid) ? 'online' : 'offline';
    buf.write(
      "<contact jid='${_esc(c.jid)}' name='${_esc(c.name)}' "
      "presence='$presence' "
      "lastSeen='${c.lastSeen.toUtc().toIso8601String()}'"
      "${c.avatar != null ? " avatar='${_esc(c.avatar!)}'" : ''}/>",
    );
  }
  buf.write('</roster>');
  xmpp.send(buf.toString());
}

void _broadcastPresence(String jid, String show) {
  final stanza =
      "<presence from='${_esc(jid)}' show='${_esc(show)}' ts='${_now()}'/>";
  for (final s in _online.values) {
    if (s.jid == jid) continue;
    s.xmpp.send(stanza);
  }
}

void _flushOffline(XmppOverQuicConnection xmpp, String jid) {
  final q = _offlineQueue.remove(jid);
  if (q == null) return;
  for (final s in q) {
    xmpp.send(s);
  }
}
