import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'models/call.dart';
import 'screens/call_screen.dart';
import 'screens/home_screen.dart';
import 'screens/login_screen.dart';
import 'services/call_service.dart';
import 'services/xmpp_service.dart';
import 'theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final xmpp = XmppService();
  final calls = CallService(xmpp);
  unawaited(xmpp.init());
  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider<XmppService>.value(value: xmpp),
        ChangeNotifierProvider<CallService>.value(value: calls),
      ],
      child: const WhatsAppCloneApp(),
    ),
  );
}

void unawaited(Future<void> _) {}

final GlobalKey<NavigatorState> _navKey = GlobalKey<NavigatorState>();

class WhatsAppCloneApp extends StatelessWidget {
  const WhatsAppCloneApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'WhatsApp Clone (XMPP/QUIC)',
      debugShowCheckedModeBanner: false,
      theme: WaTheme.light(),
      navigatorKey: _navKey,
      home: const _Root(),
      builder: (context, child) =>
          _CallRouter(child: child ?? const SizedBox()),
    );
  }
}

/// Watches `CallService` and pushes [CallScreen] when an incoming call
/// arrives so the user sees the ringing UI no matter which tab they're on.
class _CallRouter extends StatefulWidget {
  final Widget child;
  const _CallRouter({required this.child});

  @override
  State<_CallRouter> createState() => _CallRouterState();
}

class _CallRouterState extends State<_CallRouter> {
  CallService? _call;
  String? _shownCallId;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final c = context.read<CallService>();
    if (_call != c) {
      _call?.removeListener(_maybeShow);
      _call = c;
      _call!.addListener(_maybeShow);
    }
  }

  @override
  void dispose() {
    _call?.removeListener(_maybeShow);
    super.dispose();
  }

  void _maybeShow() {
    final c = _call?.active;
    if (c == null) {
      _shownCallId = null;
      return;
    }
    if (c.direction != CallDirection.incoming) return;
    if (_shownCallId == c.id) return;
    _shownCallId = c.id;
    final nav = _navKey.currentState;
    if (nav == null) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      nav.push(MaterialPageRoute<void>(builder: (_) => const CallScreen()));
    });
  }

  @override
  Widget build(BuildContext context) => widget.child;
}

class _Root extends StatelessWidget {
  const _Root();

  @override
  Widget build(BuildContext context) {
    final xmpp = context.watch<XmppService>();
    if (!xmpp.booted) return const _Splash();
    return xmpp.isAuthenticated ? const HomeScreen() : const LoginScreen();
  }
}

class _Splash extends StatelessWidget {
  const _Splash();
  @override
  Widget build(BuildContext context) => const Scaffold(
    backgroundColor: WaTheme.primary,
    body: Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.chat_bubble, color: Colors.white, size: 64),
          SizedBox(height: 16),
          Text(
            'WhatsApp Clone (XMPP/QUIC)',
            style: TextStyle(color: Colors.white, fontSize: 16),
          ),
        ],
      ),
    ),
  );
}
