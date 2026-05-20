import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../services/xmpp_service.dart';
import '../theme.dart';
import 'calls_screen.dart';
import 'chat_list_screen.dart';
import 'chat_screen.dart';
import 'new_group_screen.dart';
import 'profile_screen.dart';
import 'status_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs;

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 4, vsync: this, initialIndex: 1)
      ..addListener(() => setState(() {}));
  }

  @override
  void dispose() {
    _tabs.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // watch so the AppBar etc. rebuild on connection/presence changes
    context.watch<XmppService>();
    return Scaffold(
      appBar: AppBar(
        title: const Text('WhatsApp Clone'),
        bottom: TabBar(
          controller: _tabs,
          tabs: const [
            Tab(icon: Icon(Icons.camera_alt)),
            Tab(text: 'CHATS'),
            Tab(text: 'STATUS'),
            Tab(text: 'CALLS'),
          ],
        ),
        actions: [
          IconButton(icon: const Icon(Icons.search), onPressed: () {}),
          PopupMenuButton<String>(
            onSelected: (v) async {
              if (v == 'profile') {
                Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const ProfileScreen()),
                );
              } else if (v == 'logout') {
                await context.read<XmppService>().logout();
              }
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'profile', child: Text('Profile')),
              PopupMenuItem(value: 'logout', child: Text('Log out')),
            ],
          ),
        ],
      ),
      body: TabBarView(
        controller: _tabs,
        children: const [
          _CameraTab(),
          ChatListScreen(),
          StatusScreen(),
          CallsScreen(),
        ],
      ),
      floatingActionButton: _tabs.index == 1
          ? FloatingActionButton(
              child: const Icon(Icons.chat),
              onPressed: () => _pickContact(context),
            )
          : null,
    );
  }

  Future<void> _pickContact(BuildContext context) async {
    final xmpp = context.read<XmppService>();
    final contacts = xmpp.contacts.values.toList()
      ..sort((a, b) => a.name.compareTo(b.name));
    await showModalBottomSheet<void>(
      context: context,
      builder: (sheetCtx) => SafeArea(
        child: ListView(
          children: [
            ListTile(
              leading: const Icon(Icons.group_add, color: WaTheme.primary),
              title: const Text('New group'),
              onTap: () {
                Navigator.pop(sheetCtx);
                Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const NewGroupScreen()),
                );
              },
            ),
            const Divider(height: 1),
            if (contacts.isEmpty)
              const Padding(
                padding: EdgeInsets.all(24),
                child: Text('No contacts yet — others must connect first.'),
              ),
            for (final c in contacts)
              ListTile(
                leading: CircleAvatar(
                  backgroundColor: WaTheme.secondary,
                  child: Text(
                    c.name.isEmpty ? '?' : c.name[0].toUpperCase(),
                    style: const TextStyle(color: Colors.white),
                  ),
                ),
                title: Text(c.name),
                subtitle: Text(c.jid),
                trailing: c.online
                    ? const Icon(Icons.circle, size: 10, color: WaTheme.accent)
                    : null,
                onTap: () {
                  Navigator.pop(sheetCtx);
                  xmpp.requestHistory(c.jid);
                  Navigator.of(context).push(
                    MaterialPageRoute(
                      builder: (_) => ChatScreen(peerId: c.jid),
                    ),
                  );
                },
              ),
          ],
        ),
      ),
    );
  }
}

class _CameraTab extends StatelessWidget {
  const _CameraTab();
  @override
  Widget build(BuildContext context) => const Center(
    child: Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(Icons.camera_alt, size: 64, color: Colors.black26),
        SizedBox(height: 12),
        Text('Camera (stub)'),
      ],
    ),
  );
}
