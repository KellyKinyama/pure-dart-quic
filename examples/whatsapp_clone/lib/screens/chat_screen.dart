// ChatScreen — flutter_chat_ui (Flyer Chat) v2 driven by XmppService.
//
// The XmppService is the canonical store. A per-screen InMemoryChatController
// mirrors the matching ChatThread's messages. Any time the service notifies
// (new stanza, receipt, presence) we diff and either insert new messages or
// update existing ones (status changes).

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_chat_core/flutter_chat_core.dart' as fcc;
import 'package:flutter_chat_ui/flutter_chat_ui.dart';
import 'package:flyer_chat_image_message/flyer_chat_image_message.dart';
import 'package:flyer_chat_text_message/flyer_chat_text_message.dart';
import 'package:image_picker/image_picker.dart';
import 'package:provider/provider.dart';

import '../models/models.dart' as app;
import '../services/call_service.dart';
import '../services/xmpp_service.dart';
import '../theme.dart';
import '../widgets/avatar.dart';
import 'call_screen.dart';

class ChatScreen extends StatefulWidget {
  final String peerId;
  const ChatScreen({super.key, required this.peerId});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final fcc.InMemoryChatController _ctrl = fcc.InMemoryChatController();
  late XmppService _xmpp;
  Timer? _typingTimer;
  bool _typingSent = false;
  int _synced = 0;
  final Map<String, app.MessageStatus> _lastStatus =
      <String, app.MessageStatus>{};

  @override
  void initState() {
    super.initState();
    _xmpp = context.read<XmppService>();
    _xmpp.addListener(_sync);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _xmpp.requestHistory(widget.peerId);
      _sync();
    });
  }

  @override
  void dispose() {
    _xmpp.removeListener(_sync);
    _typingTimer?.cancel();
    if (_typingSent) {
      _xmpp.sendChatState(widget.peerId, 'paused');
    }
    _ctrl.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------
  // Sync XmppService → InMemoryChatController.
  // ---------------------------------------------------------------------
  void _sync() {
    final th = _xmpp.threads[widget.peerId];
    if (th == null) return;

    if (_synced > th.messages.length) {
      // History replaced (history-result) — reset everything.
      _synced = 0;
      _lastStatus.clear();
      _ctrl.setMessages(const []);
    }

    while (_synced < th.messages.length) {
      final m = th.messages[_synced++];
      _ctrl.insertMessage(_toFlyer(m));
      _lastStatus[m.id] = m.status;
      if (!m.fromMe) {
        // Auto-mark peer messages as read.
        _xmpp.sendReadReceipt(m.id, widget.peerId);
      }
    }

    // Diff status of existing messages (delivery / read receipts).
    for (final m in th.messages) {
      final prev = _lastStatus[m.id];
      if (prev != null && prev != m.status) {
        _lastStatus[m.id] = m.status;
        final oldMsg = _ctrl.messages.firstWhere(
          (x) => x.id == m.id,
          orElse: () => _toFlyer(m),
        );
        _ctrl.updateMessage(oldMsg, _toFlyer(m));
      }
    }

    if (th.unread != 0) th.unread = 0;
  }

  // ---------------------------------------------------------------------
  // ChatMessage → flyer Message
  // ---------------------------------------------------------------------
  fcc.Message _toFlyer(app.ChatMessage m) {
    final media = _extractMedia(m.body);
    final base = <Symbol, Object?>{};
    if (media != null) {
      final src = 'data:${media.mime};base64,${media.b64}';
      return fcc.ImageMessage(
        id: m.id,
        authorId: m.from,
        createdAt: m.ts.toUtc(),
        source: src,
        status: _mapStatus(m.status, m.fromMe),
        sentAt: _maybeTs(m.status, m.fromMe, sent: true),
        deliveredAt: _maybeTs(m.status, m.fromMe, delivered: true),
        seenAt: _maybeTs(m.status, m.fromMe, seen: true),
      );
    }
    base.clear();
    return fcc.TextMessage(
      id: m.id,
      authorId: m.from,
      createdAt: m.ts.toUtc(),
      text: m.body,
      status: _mapStatus(m.status, m.fromMe),
      sentAt: _maybeTs(m.status, m.fromMe, sent: true),
      deliveredAt: _maybeTs(m.status, m.fromMe, delivered: true),
      seenAt: _maybeTs(m.status, m.fromMe, seen: true),
    );
  }

  fcc.MessageStatus? _mapStatus(app.MessageStatus s, bool fromMe) {
    if (!fromMe) return null;
    switch (s) {
      case app.MessageStatus.sending:
        return fcc.MessageStatus.sending;
      case app.MessageStatus.sent:
        return fcc.MessageStatus.sent;
      case app.MessageStatus.delivered:
        return fcc.MessageStatus.delivered;
      case app.MessageStatus.read:
        return fcc.MessageStatus.seen;
      case app.MessageStatus.failed:
        return fcc.MessageStatus.error;
    }
  }

  DateTime? _maybeTs(
    app.MessageStatus s,
    bool fromMe, {
    bool sent = false,
    bool delivered = false,
    bool seen = false,
  }) {
    if (!fromMe) return null;
    final now = DateTime.now().toUtc();
    if (seen && s == app.MessageStatus.read) return now;
    if (delivered &&
        (s == app.MessageStatus.delivered || s == app.MessageStatus.read)) {
      return now;
    }
    if (sent && s != app.MessageStatus.sending) return now;
    return null;
  }

  // ---------------------------------------------------------------------
  // User resolver
  // ---------------------------------------------------------------------
  Future<fcc.User?> _resolveUser(fcc.UserID id) async {
    if (id == _xmpp.myJid) {
      return fcc.User(id: id, name: _xmpp.myName ?? id);
    }
    final c = _xmpp.contacts[id];
    return fcc.User(id: id, name: c?.name ?? id);
  }

  // ---------------------------------------------------------------------
  // Send / attach
  // ---------------------------------------------------------------------
  bool get _isGroup => _xmpp.threads[widget.peerId]?.isGroup ?? false;

  void _onSend(String text) {
    final t = text.trim();
    if (t.isEmpty) return;
    _xmpp.sendText(widget.peerId, t, isGroup: _isGroup);
    if (_typingSent) {
      _xmpp.sendChatState(widget.peerId, 'paused');
      _typingSent = false;
    }
  }

  Future<void> _onAttach() async {
    try {
      final picker = ImagePicker();
      final f = await picker.pickImage(
        source: ImageSource.gallery,
        imageQuality: 70,
      );
      if (f == null) return;
      final bytes = await f.readAsBytes();
      await _xmpp.sendMedia(
        widget.peerId,
        'image/jpeg',
        f.name,
        bytes,
        isGroup: _isGroup,
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Image picker error: $e')));
      }
    }
  }

  // Send chat-state ‘composing’ when text changes. Hook into the default
  // composer via builder isn't trivial; we attach a listener to focus
  // instead — see [_onComposerActivity].
  void _onComposerActivity() {
    if (!_typingSent) {
      _xmpp.sendChatState(widget.peerId, 'composing');
      _typingSent = true;
    }
    _typingTimer?.cancel();
    _typingTimer = Timer(const Duration(seconds: 2), () {
      _xmpp.sendChatState(widget.peerId, 'paused');
      _typingSent = false;
    });
  }

  // ---------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------
  @override
  Widget build(BuildContext context) {
    final xmpp = context.watch<XmppService>();
    final th = xmpp.threads[widget.peerId];
    final contact = xmpp.contacts[widget.peerId];
    final isGroup = th?.isGroup ?? false;
    final title = th?.displayName ?? contact?.name ?? widget.peerId;
    final sub = th?.typingPeer != null
        ? 'typing…'
        : (isGroup
              ? '${xmpp.groups[widget.peerId]?.members.length ?? 0} members'
              : (contact?.online == true ? 'online' : 'offline'));
    final me = xmpp.myJid ?? '';

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(
          children: [
            WaAvatar(name: title, online: contact?.online ?? false),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(title, maxLines: 1, overflow: TextOverflow.ellipsis),
                  Text(
                    sub,
                    style: const TextStyle(fontSize: 12, color: Colors.white70),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.videocam),
            tooltip: 'Video call',
            onPressed: isGroup ? null : () => _startCall(video: true),
          ),
          IconButton(
            icon: const Icon(Icons.call),
            tooltip: 'Voice call',
            onPressed: isGroup ? null : () => _startCall(video: false),
          ),
        ],
      ),
      body: NotificationListener<ScrollNotification>(
        onNotification: (_) {
          _onComposerActivity();
          return false;
        },
        child: Chat(
          chatController: _ctrl,
          currentUserId: me,
          resolveUser: _resolveUser,
          onMessageSend: _onSend,
          onAttachmentTap: _onAttach,
          backgroundColor: WaTheme.bgChat,
          builders: fcc.Builders(
            textMessageBuilder:
                (
                  ctx,
                  msg,
                  index, {
                  required bool isSentByMe,
                  fcc.MessageGroupStatus? groupStatus,
                }) {
                  return FlyerChatTextMessage(
                    message: msg,
                    index: index,
                    sentBackgroundColor: WaTheme.msgOut,
                    receivedBackgroundColor: WaTheme.msgIn,
                  );
                },
            imageMessageBuilder:
                (
                  ctx,
                  msg,
                  index, {
                  required bool isSentByMe,
                  fcc.MessageGroupStatus? groupStatus,
                }) {
                  return FlyerChatImageMessage(
                    message: msg,
                    index: index,
                    customImageProvider: _providerFor(msg.source),
                  );
                },
          ),
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------
  ImageProvider? _providerFor(String src) {
    if (src.startsWith('data:')) {
      final i = src.indexOf(',');
      if (i < 0) return null;
      try {
        return MemoryImage(
          Uint8List.fromList(base64Decode(src.substring(i + 1))),
        );
      } catch (_) {
        return null;
      }
    }
    return null; // fall back to the default network image
  }

  static final RegExp _mediaRe = RegExp(
    r"<media\s+type='([^']*)'(?:\s+name='[^']*')?>([A-Za-z0-9+/=]+)</media>",
  );

  _Media? _extractMedia(String body) {
    final m = _mediaRe.firstMatch(body);
    if (m == null) return null;
    return _Media(m.group(1) ?? 'image/jpeg', m.group(2) ?? '');
  }

  Future<void> _startCall({required bool video}) async {
    final call = context.read<CallService>();
    if (call.active != null) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Already in a call')));
      return;
    }
    await call.startCall(widget.peerId, video: video);
    if (!mounted) return;
    Navigator.of(
      context,
    ).push(MaterialPageRoute<void>(builder: (_) => const CallScreen()));
  }
}

class _Media {
  final String mime;
  final String b64;
  _Media(this.mime, this.b64);
}
