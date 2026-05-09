// SocketIoOverWt — browser client for the Dart Socket.IO-over-
// WebTransport server (bin/socketio_server.dart). Implements the same
// length-prefixed JSON wire format as the Dart client.
//
// Public API mirrors socket.io-client:
//
//   const io = await SocketIoOverWt.connect({
//     url: 'https://localhost:4444/socket.io',
//     namespace: '/',
//   });
//   io.on('msg', (args) => console.log('msg', args));
//   io.emit('say', ['hello']);
//   const reply = await io.emitWithAck('whoami');   // -> ['sid-3']
//   io.disconnect();
//
// Wire format (control bidi stream):
//   frame := varint(jsonByteLength) || utf8(JSON)
//
// Packet types (must match Dart impl):
const PKT = Object.freeze({
  CONNECT: 0,
  CONNECT_ACK: 1,
  DISCONNECT: 2,
  EVENT: 3,
  ACK: 4,
  JOIN: 5,
  LEAVE: 6,
  ERROR: 7,
});

// ---------------------------------------------------------------------
// QUIC variable-length integer (RFC 9000 §16) — same encoding the
// Dart side uses.
// ---------------------------------------------------------------------
function writeVarInt(value) {
  if (value < 0) throw new RangeError('varint value cannot be negative');
  if (value < 0x40) return new Uint8Array([value]);
  if (value < 0x4000) {
    return new Uint8Array([0x40 | (value >> 8), value & 0xff]);
  }
  if (value < 0x40000000) {
    return new Uint8Array([
      0x80 | ((value >> 24) & 0xff),
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff,
    ]);
  }
  // 8-byte form. JS numbers are safe up to 2^53.
  const hi = Math.floor(value / 0x100000000);
  const lo = value >>> 0;
  return new Uint8Array([
    0xc0 | ((hi >> 24) & 0xff),
    (hi >> 16) & 0xff,
    (hi >> 8) & 0xff,
    hi & 0xff,
    (lo >> 24) & 0xff,
    (lo >> 16) & 0xff,
    (lo >> 8) & 0xff,
    lo & 0xff,
  ]);
}

function readVarInt(buf, offset) {
  if (offset >= buf.length) return null;
  const first = buf[offset];
  const prefix = first >> 6;
  if (prefix === 0) return { value: first & 0x3f, byteLength: 1 };
  if (prefix === 1) {
    if (offset + 1 >= buf.length) return null;
    return { value: ((first & 0x3f) << 8) | buf[offset + 1], byteLength: 2 };
  }
  if (prefix === 2) {
    if (offset + 3 >= buf.length) return null;
    const v =
      ((first & 0x3f) << 24) |
      (buf[offset + 1] << 16) |
      (buf[offset + 2] << 8) |
      buf[offset + 3];
    return { value: v >>> 0, byteLength: 4 };
  }
  if (offset + 7 >= buf.length) return null;
  const hi =
    ((first & 0x3f) * 0x1000000) +
    (buf[offset + 1] << 16) +
    (buf[offset + 2] << 8) +
    buf[offset + 3];
  const lo =
    (buf[offset + 4] * 0x1000000) +
    (buf[offset + 5] << 16) +
    (buf[offset + 6] << 8) +
    buf[offset + 7];
  return { value: hi * 0x100000000 + lo, byteLength: 8 };
}

// ---------------------------------------------------------------------
// Frame encode / decode
// ---------------------------------------------------------------------
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: false });

function encodeFrame(packet) {
  const body = TEXT_ENCODER.encode(JSON.stringify(packet));
  const lp = writeVarInt(body.length);
  const out = new Uint8Array(lp.length + body.length);
  out.set(lp, 0);
  out.set(body, lp.length);
  return out;
}

class FrameDecoder {
  constructor() {
    this._buf = new Uint8Array(0);
  }

  *add(chunk) {
    if (chunk.length > 0) {
      const merged = new Uint8Array(this._buf.length + chunk.length);
      merged.set(this._buf, 0);
      merged.set(chunk, this._buf.length);
      this._buf = merged;
    }
    while (true) {
      if (this._buf.length === 0) return;
      const hdr = readVarInt(this._buf, 0);
      if (!hdr) return;
      const total = hdr.byteLength + hdr.value;
      if (this._buf.length < total) return;
      const body = this._buf.subarray(hdr.byteLength, total);
      this._buf = this._buf.subarray(total).slice();
      try {
        yield JSON.parse(TEXT_DECODER.decode(body));
      } catch (e) {
        console.warn('[socketio] dropped malformed frame:', e);
      }
    }
  }
}

// ---------------------------------------------------------------------
// Public client
// ---------------------------------------------------------------------
export class SocketIoOverWt {
  /**
   * @param {WebTransport} transport
   * @param {WebTransportBidirectionalStream} ctrlStream
   * @param {string} namespace
   */
  constructor(transport, ctrlStream, namespace) {
    this._wt = transport;
    this._ctrl = ctrlStream;
    this._writer = ctrlStream.writable.getWriter();
    this._reader = ctrlStream.readable.getReader();
    this._decoder = new FrameDecoder();
    this._handlers = new Map();             // event -> Set<fn>
    this._pendingAcks = new Map();          // id -> {resolve, reject}
    this._nextAckId = 1;
    this._closed = false;
    this._disconnectListeners = new Set();
    this.namespace = namespace;
    this.id = '';

    this._readLoop();
    this._datagramLoop();
  }

  /**
   * Open a connection to a Socket.IO-over-WebTransport server.
   *
   * @param {object} opts
   * @param {string} opts.url        - https://host:port/socket.io
   * @param {string} [opts.namespace='/']
   * @param {object} [opts.transportOpts] - extra WebTransport options
   *   (e.g. { serverCertificateHashes: [...] }).
   * @param {number} [opts.timeoutMs=15000]
   * @returns {Promise<SocketIoOverWt>}
   */
  static async connect({
    url,
    namespace = '/',
    transportOpts = {},
    timeoutMs = 15000,
  }) {
    if (!('WebTransport' in globalThis)) {
      throw new Error('WebTransport API not available in this browser');
    }
    const wt = new WebTransport(url, transportOpts);
    await Promise.race([
      wt.ready,
      _timeoutPromise(timeoutMs, `WebTransport handshake to ${url}`),
    ]);

    const ctrl = await wt.createBidirectionalStream();
    const client = new SocketIoOverWt(wt, ctrl, namespace);
    client._send({ t: PKT.CONNECT, ns: namespace });

    await Promise.race([
      new Promise((resolve, reject) => {
        client._connectResolve = resolve;
        client._connectReject = reject;
      }),
      _timeoutPromise(timeoutMs, 'Socket.IO CONNECT_ACK'),
    ]);
    return client;
  }

  // -----------------------------------------------------------------
  // socket.io API
  // -----------------------------------------------------------------

  on(event, handler) {
    if (!this._handlers.has(event)) this._handlers.set(event, new Set());
    this._handlers.get(event).add(handler);
    return this;
  }

  off(event, handler) {
    if (!handler) {
      this._handlers.delete(event);
      return this;
    }
    this._handlers.get(event)?.delete(handler);
    return this;
  }

  once(event, handler) {
    const wrap = (...args) => {
      this.off(event, wrap);
      handler(...args);
    };
    return this.on(event, wrap);
  }

  emit(event, args = [], { volatile = false } = {}) {
    const pkt = { t: PKT.EVENT, e: event, a: args };
    if (volatile) {
      this._sendDatagram(pkt);
    } else {
      this._send(pkt);
    }
    return this;
  }

  emitWithAck(event, args = [], { timeoutMs = 30000 } = {}) {
    const id = this._nextAckId++;
    const p = new Promise((resolve, reject) => {
      this._pendingAcks.set(id, { resolve, reject });
    });
    this._send({ t: PKT.EVENT, e: event, a: args, id });
    return Promise.race([
      p,
      _timeoutPromise(timeoutMs, `ack for "${event}"`).finally(() =>
        this._pendingAcks.delete(id)
      ),
    ]);
  }

  join(room) {
    this._send({ t: PKT.JOIN, r: room });
  }

  leave(room) {
    this._send({ t: PKT.LEAVE, r: room });
  }

  onDisconnect(handler) {
    this._disconnectListeners.add(handler);
    return () => this._disconnectListeners.delete(handler);
  }

  async disconnect() {
    if (this._closed) return;
    this._closed = true;
    try { this._send({ t: PKT.DISCONNECT }); } catch (_) {}
    try { await this._writer.close(); } catch (_) {}
    try { await this._reader.cancel(); } catch (_) {}
    try { this._wt.close(); } catch (_) {}
    this._fireDisconnect();
  }

  // -----------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------

  _send(packet) {
    if (this._closed) return;
    this._writer.write(encodeFrame(packet)).catch((e) => {
      console.warn('[socketio] write failed:', e);
    });
  }

  _sendDatagram(packet) {
    try {
      const bytes = TEXT_ENCODER.encode(JSON.stringify(packet));
      const w = this._wt.datagrams.writable.getWriter();
      w.write(bytes).finally(() => w.releaseLock());
    } catch (e) {
      console.warn('[socketio] datagram failed:', e);
    }
  }

  async _readLoop() {
    try {
      while (!this._closed) {
        const { value, done } = await this._reader.read();
        if (done) break;
        if (!value || value.length === 0) continue;
        for (const pkt of this._decoder.add(value)) {
          this._handlePacket(pkt);
        }
      }
    } catch (e) {
      if (!this._closed) console.warn('[socketio] read loop error:', e);
    } finally {
      this._fireDisconnect();
    }
  }

  async _datagramLoop() {
    try {
      const reader = this._wt.datagrams.readable.getReader();
      while (!this._closed) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!value) continue;
        try {
          this._handlePacket(JSON.parse(TEXT_DECODER.decode(value)));
        } catch (_) { /* drop malformed datagram */ }
      }
    } catch (e) {
      if (!this._closed) console.warn('[socketio] datagram loop error:', e);
    }
  }

  _handlePacket(pkt) {
    switch (pkt.t) {
      case PKT.CONNECT_ACK:
        this.id = pkt.sid || '';
        if (this._connectResolve) {
          this._connectResolve();
          this._connectResolve = null;
          this._connectReject = null;
        }
        return;
      case PKT.DISCONNECT:
        this.disconnect();
        return;
      case PKT.EVENT: {
        const ev = pkt.e || '';
        const args = pkt.a || [];
        const ackId = pkt.id;
        let ack = null;
        if (typeof ackId === 'number') {
          ack = (reply = []) => {
            this._send({ t: PKT.ACK, id: ackId, a: reply });
          };
        }
        const set = this._handlers.get(ev);
        if (!set || set.size === 0) {
          // Implicit ack so the peer doesn't deadlock on awaitable emits.
          if (ack) ack([]);
          return;
        }
        for (const h of [...set]) {
          try { h(args, ack); } catch (e) {
            console.warn(`[socketio] handler "${ev}" threw:`, e);
          }
        }
        return;
      }
      case PKT.ACK: {
        const w = this._pendingAcks.get(pkt.id);
        if (w) {
          this._pendingAcks.delete(pkt.id);
          w.resolve(pkt.a || []);
        }
        return;
      }
      case PKT.ERROR:
        console.warn('[socketio] peer error:', pkt.msg);
        return;
      default:
        console.debug('[socketio] unknown packet', pkt);
    }
  }

  _fireDisconnect() {
    for (const fn of [...this._disconnectListeners]) {
      try { fn(); } catch (_) {}
    }
    this._disconnectListeners.clear();
    for (const w of this._pendingAcks.values()) {
      w.reject(new Error('socket disconnected'));
    }
    this._pendingAcks.clear();
  }
}

function _timeoutPromise(ms, label) {
  return new Promise((_, reject) =>
    setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms)
  );
}
