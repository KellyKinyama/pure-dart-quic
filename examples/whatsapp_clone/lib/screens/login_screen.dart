import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../services/xmpp_service.dart';
import '../theme.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _host = TextEditingController(text: '127.0.0.1');
  final _port = TextEditingController(text: '4435');
  final _name = TextEditingController();
  final _user = TextEditingController();
  bool _busy = false;
  String? _err;

  Future<void> _submit() async {
    if (_user.text.trim().isEmpty || _name.text.trim().isEmpty) return;
    setState(() {
      _busy = true;
      _err = null;
    });
    try {
      final jid = '${_user.text.trim()}@chat';
      await context.read<XmppService>().login(
        host: _host.text.trim(),
        port: int.tryParse(_port.text) ?? 4435,
        jid: jid,
        name: _name.text.trim(),
      );
    } catch (e) {
      setState(() => _err = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: WaTheme.primary,
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 380),
              child: Card(
                elevation: 6,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(
                        Icons.chat_bubble,
                        size: 48,
                        color: WaTheme.primary,
                      ),
                      const SizedBox(height: 8),
                      const Text(
                        'WhatsApp Clone',
                        style: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const Text(
                        'XMPP-over-QUIC',
                        style: TextStyle(color: Colors.black54),
                      ),
                      const SizedBox(height: 16),
                      TextField(
                        controller: _name,
                        decoration: const InputDecoration(
                          labelText: 'Display name',
                          prefixIcon: Icon(Icons.person),
                        ),
                      ),
                      TextField(
                        controller: _user,
                        decoration: const InputDecoration(
                          labelText: 'Username',
                          prefixIcon: Icon(Icons.alternate_email),
                          helperText: 'becomes username@chat',
                        ),
                      ),
                      const SizedBox(height: 8),
                      Row(
                        children: [
                          Expanded(
                            flex: 3,
                            child: TextField(
                              controller: _host,
                              decoration: const InputDecoration(
                                labelText: 'Server',
                                prefixIcon: Icon(Icons.dns),
                              ),
                            ),
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: TextField(
                              controller: _port,
                              keyboardType: TextInputType.number,
                              decoration: const InputDecoration(
                                labelText: 'Port',
                              ),
                            ),
                          ),
                        ],
                      ),
                      if (_err != null) ...[
                        const SizedBox(height: 12),
                        Text(_err!, style: const TextStyle(color: Colors.red)),
                      ],
                      const SizedBox(height: 16),
                      SizedBox(
                        width: double.infinity,
                        child: ElevatedButton(
                          style: ElevatedButton.styleFrom(
                            backgroundColor: WaTheme.accent,
                            foregroundColor: Colors.white,
                            padding: const EdgeInsets.symmetric(vertical: 14),
                          ),
                          onPressed: _busy ? null : _submit,
                          child: _busy
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: Colors.white,
                                  ),
                                )
                              : const Text('CONNECT'),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
