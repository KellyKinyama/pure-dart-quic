import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../models/models.dart';
import '../services/xmpp_service.dart';
import '../theme.dart';
import '../widgets/avatar.dart';
import 'chat_screen.dart';

class ChatListScreen extends StatelessWidget {
  const ChatListScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final xmpp = context.watch<XmppService>();
    final threads = xmpp.threads.values.toList()
      ..sort((a, b) => b.updatedAt.compareTo(a.updatedAt));

    if (threads.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(
                Icons.chat_bubble_outline,
                size: 64,
                color: Colors.black26,
              ),
              const SizedBox(height: 16),
              Text(
                xmpp.connected
                    ? 'No chats yet. Tap the + button to start one.'
                    : 'Disconnected.',
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.black54),
              ),
            ],
          ),
        ),
      );
    }

    return ListView.separated(
      itemCount: threads.length,
      separatorBuilder: (_, _) =>
          const Divider(height: 1, indent: 76, endIndent: 0),
      itemBuilder: (context, i) => _ThreadTile(thread: threads[i]),
    );
  }
}

class _ThreadTile extends StatelessWidget {
  final ChatThread thread;
  const _ThreadTile({required this.thread});

  @override
  Widget build(BuildContext context) {
    final xmpp = context.read<XmppService>();
    final last = thread.lastMessage;
    final contact = xmpp.contacts[thread.peerId];
    final preview = thread.typingPeer != null
        ? 'typing…'
        : (last == null
              ? ''
              : (last.fromMe ? 'You: ' : '') + _previewBody(last.body));
    final time = last == null ? '' : DateFormat.Hm().format(last.ts.toLocal());
    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      leading: WaAvatar(
        name: thread.displayName,
        online: thread.isGroup ? false : (contact?.online ?? false),
      ),
      title: Row(
        children: [
          Expanded(
            child: Text(
              thread.displayName,
              style: const TextStyle(fontWeight: FontWeight.w600),
              overflow: TextOverflow.ellipsis,
            ),
          ),
          Text(
            time,
            style: const TextStyle(fontSize: 12, color: Colors.black54),
          ),
        ],
      ),
      subtitle: Row(
        children: [
          Expanded(
            child: Text(
              preview,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: thread.typingPeer != null
                    ? WaTheme.secondary
                    : Colors.black54,
                fontStyle: thread.typingPeer != null
                    ? FontStyle.italic
                    : FontStyle.normal,
              ),
            ),
          ),
          if (thread.unread > 0)
            Container(
              margin: const EdgeInsets.only(left: 6),
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
              decoration: const BoxDecoration(
                color: WaTheme.accent,
                shape: BoxShape.circle,
              ),
              child: Text(
                '${thread.unread}',
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
        ],
      ),
      onTap: () {
        thread.unread = 0;
        Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => ChatScreen(peerId: thread.peerId)),
        );
      },
    );
  }

  String _previewBody(String body) {
    if (body.contains('<media')) return '📷 Media';
    return body;
  }
}
