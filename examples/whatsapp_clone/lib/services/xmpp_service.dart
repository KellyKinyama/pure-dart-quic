// XmppService: drives the QUIC + XMPP session and exposes app-level
// streams (contacts, threads, presence, typing, receipts).

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../models/models.dart';
import '../models/call.dart';

class XmppService extends ChangeNotifier {
  XmppService();

  // ---- Connection state -------------------------------------------------
  QuicClientEndpoint? _ep;
  XmppOverQuicConnection? _xmpp;
  bool _connected = false;
  bool get connected => _connected;

  bool _booted = false;
  bool get booted => _booted;

  String? _myJid;
  String? get myJid => _myJid;
  String? _myName;
  String? get myName => _myName;
  String? _host;
  String? get host => _host;
  int? _port;
  int? get port => _port;

  bool get isAuthenticated => _connected && _myJid != null;

  // ---- App state --------------------------------------------------------
  final Map<String, Contact> contacts = <String, Contact>{};
  final Map<String, ChatThread> threads = <String, ChatThread>{};
  final Map<String, Group> groups = <String, Group>{};

  final StreamController<String> _events = StreamController.broadcast();
  Stream<String> get events => _events.stream;

  final StreamController<CallSignal> _calls = StreamController.broadcast();
  Stream<CallSignal> get callSignals => _calls.stream;

  // ---- Boot / login / logout -------------------------------------------
  /// Try to restore the last session from `SharedPreferences`. Always
  /// completes; failures leave the service in a disconnected state.
  Future<void> init() async {
    final prefs = await SharedPreferences.getInstance();
    final jid = prefs.getString('jid');
    final name = prefs.getString('name');
    final host = prefs.getString('host') ?? '127.0.0.1';
    final port = prefs.getInt('port') ?? 4435;
    if (jid != null && name != null) {
      try {
        await _connect(host: host, port: port, jid: jid, name: name);
      } catch (_) {
        // ignore, user can log in manually
      }
    }
    _booted = true;
    notifyListeners();
  }

  Future<void> login({
    required String host,
    required int port,
    required String jid,
    required String name,
  }) async {
    await _connect(host: host, port: port, jid: jid, name: name);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('jid', jid);
    await prefs.setString('name', name);
    await prefs.setString('host', host);
    await prefs.setInt('port', port);
  }

  Future<void> logout() async {
    await disconnect();
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('jid');
    contacts.clear();
    threads.clear();
    groups.clear();
    _myJid = null;
    _myName = null;
    notifyListeners();
  }

  // ---- Connect (low level) ---------------------------------------------
  Future<void> _connect({
    required String host,
    required int port,
    required String jid,
    required String name,
    String? avatar,
  }) async {
    await disconnect();
    final alpns = AlpnRegistry()..register(XmppOverQuicProtocolFactory());
    final ep = await QuicClientEndpoint.connect(
      remoteAddress: InternetAddress(host),
      remotePort: port,
      authority: host,
      alpns: alpns,
      alpn: 'xmpp-quic',
    );
    _ep = ep;
    await ep.connection.ready;
    final proto = ep.protocol;
    if (proto is! XmppOverQuicClientProtocol) {
      throw StateError('expected XMPP protocol');
    }
    final xmpp = await proto.opened;
    _xmpp = xmpp;
    _myJid = jid;
    _myName = name;
    _host = host;
    _port = port;
    xmpp.stanzas.listen(_onStanza, onDone: _onDisconnected);
    final av = avatar == null ? '' : " avatar='${_escAttr(avatar)}'";
    xmpp.send("<auth jid='${_escAttr(jid)}' name='${_escAttr(name)}'$av/>");
    _connected = true;
    notifyListeners();
  }

  Future<void> disconnect() async {
    if (_xmpp != null) {
      try {
        await _xmpp!.close();
      } catch (_) {}
      _xmpp = null;
    }
    if (_ep != null) {
      try {
        await _ep!.close();
      } catch (_) {}
      _ep = null;
    }
    if (_connected) {
      _connected = false;
      notifyListeners();
    }
  }

  void _onDisconnected() {
    _connected = false;
    notifyListeners();
    _events.add('disconnected');
  }

  // ---- Outgoing ---------------------------------------------------------
  String _nextId() => 'm${DateTime.now().microsecondsSinceEpoch}';

  ChatThread _thread(String peer, {bool isGroup = false, String? name}) {
    return threads.putIfAbsent(
      peer,
      () => ChatThread(
        peerId: peer,
        displayName: name ?? contacts[peer]?.name ?? peer,
        isGroup: isGroup,
      ),
    );
  }

  Future<void> sendText(String to, String body, {bool isGroup = false}) async {
    final x = _xmpp;
    final me = _myJid;
    if (x == null || me == null) return;
    final id = _nextId();
    final tag = isGroup ? 'group-message' : 'message';
    final attr = isGroup
        ? "id='$id' group='${_escAttr(to)}' from='${_escAttr(me)}'"
        : "id='$id' from='${_escAttr(me)}' to='${_escAttr(to)}' type='chat'";
    x.send('<$tag $attr><body>${_escText(body)}</body></$tag>');
    final th = _thread(to, isGroup: isGroup);
    th.messages.add(
      ChatMessage(
        id: id,
        from: me,
        to: to,
        body: body,
        ts: DateTime.now(),
        fromMe: true,
        status: MessageStatus.sent,
        isGroup: isGroup,
      ),
    );
    th.updatedAt = DateTime.now();
    notifyListeners();
  }

  Future<void> sendMedia(
    String to,
    String mime,
    String name,
    List<int> bytes, {
    bool isGroup = false,
  }) async {
    final body =
        "<media type='${_escAttr(mime)}' name='${_escAttr(name)}'>"
        "${base64Encode(bytes)}</media>";
    // Send raw stanza so we don't double-encode the body element.
    final x = _xmpp;
    final me = _myJid;
    if (x == null || me == null) return;
    final id = _nextId();
    final tag = isGroup ? 'group-message' : 'message';
    final attr = isGroup
        ? "id='$id' group='${_escAttr(to)}' from='${_escAttr(me)}'"
        : "id='$id' from='${_escAttr(me)}' to='${_escAttr(to)}' type='chat'";
    x.send('<$tag $attr><body>$body</body></$tag>');
    final th = _thread(to, isGroup: isGroup);
    th.messages.add(
      ChatMessage(
        id: id,
        from: me,
        to: to,
        body: body,
        ts: DateTime.now(),
        fromMe: true,
        status: MessageStatus.sent,
        isGroup: isGroup,
      ),
    );
    th.updatedAt = DateTime.now();
    notifyListeners();
  }

  void sendChatState(String to, String state) {
    final x = _xmpp;
    final me = _myJid;
    if (x == null || me == null) return;
    x.send(
      "<chatstate from='${_escAttr(me)}' to='${_escAttr(to)}' "
      "state='${_escAttr(state)}'/>",
    );
  }

  void sendReadReceipt(String mid, String peer) {
    final x = _xmpp;
    final me = _myJid;
    if (x == null || me == null) return;
    x.send(
      "<receipt id='${_escAttr(mid)}' from='${_escAttr(me)}' "
      "to='${_escAttr(peer)}' type='read'/>",
    );
  }

  void requestHistory(String peer) {
    _xmpp?.send("<history with='${_escAttr(peer)}' limit='100'/>");
  }

  // ---- Call signaling --------------------------------------------------
  String newCallId() =>
      'c${DateTime.now().microsecondsSinceEpoch.toRadixString(36)}';

  void sendCallOffer({
    required String callId,
    required String to,
    required bool video,
    required String sdp,
  }) {
    final me = _myJid;
    if (me == null) return;
    _xmpp?.send(
      "<call-offer id='${_escAttr(callId)}' from='${_escAttr(me)}' "
      "to='${_escAttr(to)}' video='${video ? 1 : 0}' "
      "sdp='${base64Encode(utf8.encode(sdp))}'/>",
    );
  }

  void sendCallAnswer({
    required String callId,
    required String to,
    required String sdp,
  }) {
    final me = _myJid;
    if (me == null) return;
    _xmpp?.send(
      "<call-answer id='${_escAttr(callId)}' from='${_escAttr(me)}' "
      "to='${_escAttr(to)}' sdp='${base64Encode(utf8.encode(sdp))}'/>",
    );
  }

  void sendCallIce({
    required String callId,
    required String to,
    required String candidate,
    String? sdpMid,
    int? sdpMLineIndex,
  }) {
    final me = _myJid;
    if (me == null) return;
    final mid = sdpMid == null ? '' : " mid='${_escAttr(sdpMid)}'";
    final idx = sdpMLineIndex == null ? '' : " idx='$sdpMLineIndex'";
    _xmpp?.send(
      "<call-ice id='${_escAttr(callId)}' from='${_escAttr(me)}' "
      "to='${_escAttr(to)}'$mid$idx "
      "cand='${base64Encode(utf8.encode(candidate))}'/>",
    );
  }

  void sendCallEnd({
    required String callId,
    required String to,
    String reason = 'hangup',
  }) {
    final me = _myJid;
    if (me == null) return;
    _xmpp?.send(
      "<call-end id='${_escAttr(callId)}' from='${_escAttr(me)}' "
      "to='${_escAttr(to)}' reason='${_escAttr(reason)}'/>",
    );
  }

  void sendCallReject({
    required String callId,
    required String to,
    String reason = 'busy',
  }) {
    final me = _myJid;
    if (me == null) return;
    _xmpp?.send(
      "<call-reject id='${_escAttr(callId)}' from='${_escAttr(me)}' "
      "to='${_escAttr(to)}' reason='${_escAttr(reason)}'/>",
    );
  }

  void createGroup(String name, List<String> members) {
    final gid = 'g${DateTime.now().millisecondsSinceEpoch}';
    final mbuf = StringBuffer();
    for (final m in members) {
      mbuf.write("<member jid='${_escAttr(m)}'/>");
    }
    _xmpp?.send(
      "<group-create id='${_escAttr(gid)}' name='${_escAttr(name)}'>"
      "$mbuf</group-create>",
    );
  }

  // ---- Incoming ---------------------------------------------------------
  void _onStanza(String raw) {
    final tag = _tagOf(raw);
    switch (tag) {
      case 'auth-ok':
        _events.add('auth-ok');
        break;
      case 'roster':
        contacts.clear();
        for (final m in RegExp(r'<contact ([^/]*)/>').allMatches(raw)) {
          final body = m.group(1)!;
          final jid = _a(body, 'jid') ?? '';
          if (jid.isEmpty) continue;
          contacts[jid] = Contact(
            jid: jid,
            name: _a(body, 'name') ?? jid,
            avatar: _a(body, 'avatar'),
            online: _a(body, 'presence') == 'online',
            lastSeen:
                DateTime.tryParse(_a(body, 'lastSeen') ?? '') ?? DateTime.now(),
          );
        }
        notifyListeners();
        break;
      case 'presence':
        final from = _attr(raw, 'from');
        if (from == null) return;
        final show = _attr(raw, 'show') ?? 'offline';
        final c = contacts.putIfAbsent(
          from,
          () => Contact(jid: from, name: from),
        );
        c.online = show == 'online';
        c.lastSeen =
            DateTime.tryParse(_attr(raw, 'ts') ?? '') ?? DateTime.now();
        notifyListeners();
        break;
      case 'message':
      case 'group-message':
        final isGroup = tag == 'group-message';
        final from = _attr(raw, 'from') ?? '?';
        final to = isGroup
            ? (_attr(raw, 'group') ?? '?')
            : (_attr(raw, 'to') ?? _myJid ?? '?');
        final id = _attr(raw, 'id') ?? _nextId();
        final ts = DateTime.tryParse(_attr(raw, 'ts') ?? '') ?? DateTime.now();
        final body = _innerBody(raw);
        final peer = isGroup ? to : from;
        final th = _thread(peer, isGroup: isGroup);
        th.messages.add(
          ChatMessage(
            id: id,
            from: from,
            to: to,
            body: body,
            ts: ts,
            fromMe: false,
            status: MessageStatus.delivered,
            isGroup: isGroup,
          ),
        );
        th.updatedAt = DateTime.now();
        th.unread += 1;
        notifyListeners();
        _events.add('message:$peer');
        break;
      case 'receipt':
        final mid = _attr(raw, 'id');
        final type = _attr(raw, 'type');
        if (mid == null) return;
        for (final th in threads.values) {
          for (final m in th.messages) {
            if (m.id == mid && m.fromMe) {
              if (type == 'read') {
                m.status = MessageStatus.read;
              } else if (type == 'delivered') {
                if (m.status != MessageStatus.read) {
                  m.status = MessageStatus.delivered;
                }
              }
            }
          }
        }
        notifyListeners();
        break;
      case 'chatstate':
        final from = _attr(raw, 'from');
        final state = _attr(raw, 'state');
        if (from == null) return;
        final th = _thread(from);
        th.typingPeer = state == 'composing' ? from : null;
        notifyListeners();
        break;
      case 'history-result':
        final peer = _attr(raw, 'with');
        if (peer == null) return;
        final th = _thread(peer);
        th.messages.clear();
        for (final m in RegExp(
          r'<message ([^>]*)>(.*?)</message>',
          dotAll: true,
        ).allMatches(raw)) {
          final attrs = m.group(1)!;
          final body = m.group(2) ?? '';
          final from = _a(attrs, 'from') ?? '';
          final to = _a(attrs, 'to') ?? '';
          final id = _a(attrs, 'id') ?? _nextId();
          final ts = DateTime.tryParse(_a(attrs, 'ts') ?? '') ?? DateTime.now();
          final innerBody =
              RegExp(
                r'<body>(.*?)</body>',
                dotAll: true,
              ).firstMatch(body)?.group(1) ??
              body;
          th.messages.add(
            ChatMessage(
              id: id,
              from: from,
              to: to,
              body: innerBody,
              ts: ts,
              fromMe: from == _myJid,
              status: MessageStatus.delivered,
            ),
          );
        }
        notifyListeners();
        break;
      case 'group-info':
        final gid = _attr(raw, 'id');
        final name = _attr(raw, 'name') ?? '';
        if (gid == null) return;
        final members = <String>{};
        for (final m in RegExp(r"<member jid='([^']+)'/>").allMatches(raw)) {
          members.add(m.group(1)!);
        }
        groups[gid] = Group(id: gid, name: name, members: members);
        _thread(gid, isGroup: true, name: name).displayName = name;
        notifyListeners();
        break;
      case 'call-offer':
      case 'call-answer':
      case 'call-ice':
      case 'call-end':
      case 'call-reject':
      case 'call-cancel':
        _emitCallSignal(tag, raw);
        break;
    }
  }

  void _emitCallSignal(String tag, String raw) {
    final id = _attr(raw, 'id') ?? '';
    final from = _attr(raw, 'from') ?? '';
    final to = _attr(raw, 'to') ?? '';
    CallSignalKind kind;
    switch (tag) {
      case 'call-offer':
        kind = CallSignalKind.offer;
        break;
      case 'call-answer':
        kind = CallSignalKind.answer;
        break;
      case 'call-ice':
        kind = CallSignalKind.ice;
        break;
      case 'call-end':
        kind = CallSignalKind.end;
        break;
      case 'call-reject':
        kind = CallSignalKind.reject;
        break;
      default:
        kind = CallSignalKind.cancel;
    }
    String? decodeAttr(String name) {
      final v = _attr(raw, name);
      if (v == null) return null;
      try {
        return utf8.decode(base64Decode(v));
      } catch (_) {
        return v;
      }
    }

    _calls.add(
      CallSignal(
        kind: kind,
        callId: id,
        from: from,
        to: to,
        video: (_attr(raw, 'video') ?? '0') == '1',
        sdp: decodeAttr('sdp'),
        candidate: decodeAttr('cand'),
        sdpMid: _attr(raw, 'mid'),
        sdpMLineIndex: int.tryParse(_attr(raw, 'idx') ?? ''),
        reason: _attr(raw, 'reason'),
      ),
    );
  }

  // ---- helpers ----------------------------------------------------------
  static String _escAttr(String s) => s
      .replaceAll('&', '&amp;')
      .replaceAll("'", '&apos;')
      .replaceAll('<', '&lt;');
  static String _escText(String s) => s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;');

  static String _tagOf(String raw) {
    final m = RegExp(r'<([A-Za-z\-]+)').firstMatch(raw);
    return m?.group(1) ?? '';
  }

  static String? _attr(String raw, String name) {
    final m = RegExp(" $name='([^']*)'").firstMatch(raw);
    return m?.group(1);
  }

  static String? _a(String attrs, String name) {
    final m = RegExp("$name='([^']*)'").firstMatch(attrs);
    return m?.group(1);
  }

  static String _innerBody(String raw) {
    final m = RegExp(r'<body>(.*?)</body>', dotAll: true).firstMatch(raw);
    return m?.group(1) ?? '';
  }
}
