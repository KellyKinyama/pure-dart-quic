import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../services/xmpp_service.dart';
import '../theme.dart';
import '../widgets/avatar.dart';

class NewGroupScreen extends StatefulWidget {
  const NewGroupScreen({super.key});

  @override
  State<NewGroupScreen> createState() => _NewGroupScreenState();
}

class _NewGroupScreenState extends State<NewGroupScreen> {
  final _name = TextEditingController();
  final Set<String> _picked = <String>{};

  @override
  Widget build(BuildContext context) {
    final xmpp = context.watch<XmppService>();
    final contacts = xmpp.contacts.values.toList()
      ..sort((a, b) => a.name.compareTo(b.name));
    return Scaffold(
      appBar: AppBar(
        title: const Text('New group'),
        actions: [
          IconButton(
            icon: const Icon(Icons.check),
            onPressed: _picked.isEmpty || _name.text.trim().isEmpty
                ? null
                : () {
                    context.read<XmppService>().createGroup(
                      _name.text.trim(),
                      _picked.toList(),
                    );
                    Navigator.pop(context);
                  },
          ),
        ],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(12),
            child: TextField(
              controller: _name,
              decoration: const InputDecoration(
                labelText: 'Group name',
                prefixIcon: Icon(Icons.group),
              ),
              onChanged: (_) => setState(() {}),
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: contacts.isEmpty
                ? const Center(child: Text('No contacts to add.'))
                : ListView(
                    children: [
                      for (final c in contacts)
                        CheckboxListTile(
                          secondary: WaAvatar(name: c.name, online: c.online),
                          title: Text(c.name),
                          subtitle: Text(c.jid),
                          value: _picked.contains(c.jid),
                          activeColor: WaTheme.accent,
                          onChanged: (v) => setState(() {
                            if (v == true) {
                              _picked.add(c.jid);
                            } else {
                              _picked.remove(c.jid);
                            }
                          }),
                        ),
                    ],
                  ),
          ),
        ],
      ),
    );
  }
}
