# Socket.IO over WebTransport — browser example

Browser client for `bin/socketio_server.dart`. Implements the same
length-prefixed JSON wire format as the Dart `SocketIoClient` directly
on top of the standard browser `WebTransport` API — no Socket.IO JS
library, no fallbacks, no polyfills.

## Files

| File | Purpose |
|---|---|
| [socketio_client.js](socketio_client.js) | ES module: `SocketIoOverWt` class with `connect`, `on`, `emit`, `emitWithAck`, `join`, `leave`, `disconnect`. |
| [index.html](index.html) | Demo page: connect, send chat to the lobby room, run `whoami` / `ping` ack round-trips. |

## Run it

### 1. Start the Dart server

```powershell
dart run bin/socketio_server.dart
# socket.io-over-webtransport listening on 127.0.0.1:4444
```

### 2. Serve `examples/socketio/` over HTTPS-or-localhost

WebTransport requires a **secure context**. `http://localhost` counts
as secure, so the simplest option is any static server on localhost,
for example:

```powershell
# Python
python -m http.server 8080 --directory examples/socketio
# or with Dart
dart pub global activate dhttpd
dhttpd --path examples/socketio --port 8080
```

Open <http://localhost:8080/index.html>.

### 3. Trust the self-signed cert

`pure_dart_quic` ships an in-memory self-signed cert. Browsers will
refuse the WebTransport handshake until you tell them to trust it.

#### Option A — `serverCertificateHashes` (recommended for demos)

Get the cert's SHA-256 (DER) hash from the running server's logs (the
`Fingerprint:` line) — or compute it yourself — convert it to base64,
and paste it into the **Hash** field on the page before clicking
**Connect**. The browser will accept any cert whose SPKI hash matches.

Quick conversion (PowerShell):

```powershell
# colon-separated hex -> base64
$hex = '12:34:...:AB'   # paste the colon-hex string from the server log
$bytes = $hex -split ':' | ForEach-Object { [Convert]::ToByte($_, 16) }
[Convert]::ToBase64String($bytes)
```

This works in Chrome / Edge / Opera (Firefox does not yet implement
`serverCertificateHashes`). Note: WebTransport restricts this to
**short-lived** certs (validity ≤ 14 days) — the demo cert qualifies.

#### Option B — Chrome flag

Launch Chrome with the SPKI hash whitelisted (skip per-page hash entry):

```powershell
chrome.exe --ignore-certificate-errors-spki-list=BASE64_SHA256_OF_SPKI \
           --user-data-dir="$env:TEMP\wt-demo-profile"
```

## API quick reference

```js
import { SocketIoOverWt } from './socketio_client.js';

const io = await SocketIoOverWt.connect({
  url: 'https://localhost:4444/socket.io',
  namespace: '/',
  transportOpts: { /* serverCertificateHashes, congestionControl, ... */ },
});

io.on('msg', (args, ack) => console.log('msg', args));
io.emit('say', ['hello room']);
io.emit('vol', ['lossy'], { volatile: true });   // sent via WT DATAGRAM

const reply = await io.emitWithAck('whoami');     // -> ['sid-3']

io.join('lobby');
io.leave('lobby');

io.onDisconnect(() => console.log('gone'));
await io.disconnect();
```

The wire format and every event semantic match the Dart client in
[`lib/src/app/socketio/socketio_protocol.dart`](../../lib/src/app/socketio/socketio_protocol.dart);
see the file header for the packet schema.
