import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../services/xmpp_service.dart';
import '../theme.dart';
import '../widgets/avatar.dart';

class ProfileScreen extends StatelessWidget {
  const ProfileScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final xmpp = context.watch<XmppService>();
    final name = xmpp.myName ?? '?';
    final jid = xmpp.myJid ?? '?';
    return Scaffold(
      appBar: AppBar(title: const Text('Profile')),
      body: ListView(
        children: [
          const SizedBox(height: 24),
          Center(
            child: WaAvatar(name: name, online: xmpp.connected, size: 96),
          ),
          const SizedBox(height: 12),
          Center(
            child: Text(
              name,
              style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w600),
            ),
          ),
          Center(
            child: Text(jid, style: const TextStyle(color: Colors.black54)),
          ),
          const SizedBox(height: 24),
          const Divider(),
          ListTile(
            leading: const Icon(Icons.cloud_done, color: WaTheme.primary),
            title: const Text('Transport'),
            subtitle: Text(
              'XMPP-over-QUIC — ${xmpp.connected ? 'connected' : 'disconnected'}'
              '${xmpp.host == null ? '' : ' @ ${xmpp.host}:${xmpp.port}'}',
            ),
          ),
          ListTile(
            leading: const Icon(Icons.people_alt, color: WaTheme.primary),
            title: const Text('Contacts'),
            subtitle: Text('${xmpp.contacts.length} known'),
          ),
          ListTile(
            leading: const Icon(Icons.chat, color: WaTheme.primary),
            title: const Text('Chats'),
            subtitle: Text('${xmpp.threads.length} threads'),
          ),
        ],
      ),
    );
  }
}
