# WhatsApp Clone over XMPP-over-QUIC

A Flutter demo client + Dart server that speak **XMPP over QUIC** using the
[`pure_dart_quic`](../../README.md) stack (ALPN `xmpp-quic`).

The Flutter client uses:

- **`provider`** for state management (the `XmppService` is a
  `ChangeNotifier` exposed via `ChangeNotifierProvider`; screens consume
  it with `context.watch` / `context.read`).
- **`flutter_chat_ui`** (Flyer Chat v2) for the chat surface, with
  `InMemoryChatController`, `FlyerChatTextMessage`, and
  `FlyerChatImageMessage`. Inline base64 images travel as `data:` URLs
  and are decoded into `MemoryImage` providers via a builder.

The wire format is length-prefixed XML stanzas on a single bidirectional
QUIC stream (see `lib/src/app/xmpp/xmpp_protocol.dart`). On top of that the
client and server implement a tiny WhatsApp-flavoured profile:

| Feature                  | Stanza                                      |
| ------------------------ | ------------------------------------------- |
| Login                    | `<auth jid=… name=… avatar=…/>` → `<auth-ok/>` |
| Roster push              | `<roster>…<contact .../>…</roster>`         |
| Presence                 | `<presence from=… show='online'/>`          |
| Direct message           | `<message id=… from=… to=… ts=…><body>…</body></message>` |
| Delivery / read receipts | `<receipt id=… type='delivered\|read'/>`    |
| Typing indicator         | `<chatstate state='composing\|paused'/>`    |
| History                  | `<history with=… limit=…/>` → `<history-result>` |
| Group create             | `<group-create id=… name=…><member .../></group-create>` |
| Group message            | `<group-message id=… group=… from=…>…</group-message>` |
| Media (image)            | `<body><media type=… name=…>BASE64</media></body>` |

This is a research demo using the engine from this repository — no
congestion control, no retry, no migration.

## Run

From the **repo root** (so the `path:` dependency on `pure_dart_quic`
resolves):

```powershell
# 1. Start the server (UDP/QUIC, ALPN xmpp-quic).
dart run examples/whatsapp_clone/server/whatsapp_server.dart            # default :4435
dart run examples/whatsapp_clone/server/whatsapp_server.dart 5555       # custom port

# 2. Build / launch the Flutter client.
cd examples/whatsapp_clone
flutter pub get
flutter run -d windows          # or: -d android
```

Log in with any username (e.g. `alice`) and display name. Start a second
client with a different username and you'll see each other in the roster.

## Layout

```
examples/whatsapp_clone/
├── pubspec.yaml                     # path-dep on ../../  (pure_dart_quic)
├── server/whatsapp_server.dart      # multi-client XMPP-over-QUIC server
└── lib/
    ├── main.dart                    # ChangeNotifierProvider + boot
    ├── theme.dart                   # WhatsApp palette
    ├── models/models.dart
    ├── services/xmpp_service.dart   # ChangeNotifier — connection + roster + threads
    ├── widgets/avatar.dart
    └── screens/
        ├── login_screen.dart
        ├── home_screen.dart         # Camera / Chats / Status / Calls
        ├── chat_list_screen.dart
        ├── chat_screen.dart         # Flyer Chat — text + image + receipts
        ├── status_screen.dart
        ├── calls_screen.dart
        ├── profile_screen.dart
        └── new_group_screen.dart
```

## Notes / limitations

- The Flutter **web** target won't work — QUIC needs `dart:io` UDP. Use
  Windows or Android.
- All state is in-memory on the server; restarting drops history.
- Auth is trust-the-name; there is no password / SASL.
- Image picker uses `image_picker`; behavior depends on platform support.
