// MQTT-over-QUIC (draft-ietf-quic-mqtt style).
//
// Wire format:
//   * One bidirectional QUIC stream per MQTT session (the "MQTT
//     stream"). The client opens it; the server takes the first
//     inbound bidi stream as the MQTT stream.
//   * MQTT control packets are written with their *native* MQTT
//     framing — a 1-byte fixed header (packet type + flags) followed
//     by a variable-length integer "Remaining Length" (1–4 bytes,
//     MQTT v3.1.1 / v5.0 §1.5.5) and then the variable header +
//     payload. No additional framing is added on top of MQTT.
//   * QUIC already provides TLS, so MQTT's TLS layer is not used.
//
// API:
//   * `MqttOverQuicConnection.packets` — inbound `MqttPacket` stream.
//   * `MqttOverQuicConnection.send(MqttPacket p)` — send a packet.
//   * `MqttOverQuicConnection.opened` — completes once the bidi
//     stream is established.
//
// This module is research-grade: it frames raw control packets but
// does not implement MQTT session semantics (CONNECT/SUBSCRIBE/etc.
// are left to the application).
//
// ALPN: `mqtt`.

import 'dart:async';
import 'dart:typed_data';

import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String mqttAlpn = 'mqtt';

/// MQTT control packet types (MQTT v5.0 §2.1.2). The numeric value
/// is the upper nibble of the fixed header byte.
class MqttPacketType {
  static const int connect = 1;
  static const int connack = 2;
  static const int publish = 3;
  static const int puback = 4;
  static const int pubrec = 5;
  static const int pubrel = 6;
  static const int pubcomp = 7;
  static const int subscribe = 8;
  static const int suback = 9;
  static const int unsubscribe = 10;
  static const int unsuback = 11;
  static const int pingreq = 12;
  static const int pingresp = 13;
  static const int disconnect = 14;
  static const int auth = 15;
}

/// One MQTT control packet, decomposed into its fixed-header parts
/// and an opaque body (variable header + payload concatenated).
class MqttPacket {
  /// Packet type (upper nibble of the fixed header byte). One of the
  /// constants in [MqttPacketType].
  final int type;

  /// Lower nibble of the fixed header byte (per-packet-type flags;
  /// e.g. PUBLISH carries DUP/QoS/RETAIN here).
  final int flags;

  /// Variable header + payload, opaque to this module.
  final Uint8List body;

  MqttPacket(this.type, this.flags, this.body);

  /// Convenience for packets that carry no flags (the vast majority).
  MqttPacket.simple(int type, Uint8List body) : this(type, 0, body);

  @override
  String toString() =>
      'MqttPacket(type=$type, flags=0x${flags.toRadixString(16)}, '
      'len=${body.length})';
}

/// Encode a Variable Byte Integer (MQTT v5.0 §1.5.5). 1–4 bytes.
Uint8List _encodeVarInt(int value) {
  if (value < 0 || value > 268435455) {
    throw ArgumentError('MQTT VarInt out of range: $value');
  }
  final out = <int>[];
  var v = value;
  do {
    var byte = v & 0x7f;
    v >>= 7;
    if (v > 0) byte |= 0x80;
    out.add(byte);
  } while (v > 0);
  return Uint8List.fromList(out);
}

/// Decode a Variable Byte Integer starting at [offset] in [data].
/// Returns `(value, bytesConsumed)` or `null` if more bytes are needed.
({int value, int consumed})? _decodeVarInt(Uint8List data, int offset) {
  var multiplier = 1;
  var value = 0;
  var i = 0;
  while (true) {
    if (offset + i >= data.length) return null;
    final byte = data[offset + i];
    value += (byte & 0x7f) * multiplier;
    i++;
    if ((byte & 0x80) == 0) return (value: value, consumed: i);
    multiplier *= 128;
    if (multiplier > 128 * 128 * 128) {
      throw FormatException('MQTT VarInt malformed');
    }
  }
}

/// A logical MQTT-over-QUIC session multiplexed onto a single bidi
/// QUIC stream. Owns its own MQTT framing state.
class MqttOverQuicConnection {
  final QuicStream stream;
  final StreamController<MqttPacket> _packets = StreamController<MqttPacket>();

  final BytesBuilder _buf = BytesBuilder();
  StreamSubscription<Uint8List>? _sub;

  MqttOverQuicConnection._(this.stream) {
    _sub = stream.incoming.listen(
      _onChunk,
      onDone: () {
        if (!_packets.isClosed) _packets.close();
      },
    );
  }

  /// Inbound MQTT control packets.
  Stream<MqttPacket> get packets => _packets.stream;

  /// Send one MQTT control packet. Writes the fixed header
  /// (type+flags byte and variable-length "Remaining Length") followed
  /// by the body.
  void send(MqttPacket p) {
    final header = (p.type & 0x0f) << 4 | (p.flags & 0x0f);
    final remLen = _encodeVarInt(p.body.length);
    final out = Uint8List(1 + remLen.length + p.body.length);
    out[0] = header;
    out.setRange(1, 1 + remLen.length, remLen);
    out.setRange(1 + remLen.length, out.length, p.body);
    stream.write(out);
  }

  Future<void> close() async {
    await _sub?.cancel();
    if (!_packets.isClosed) await _packets.close();
    await stream.close();
  }

  void _onChunk(Uint8List chunk) {
    _buf.add(chunk);
    while (true) {
      final view = _buf.toBytes();
      if (view.isEmpty) return;
      final header = view[0];
      final lenInfo = _decodeVarInt(view, 1);
      if (lenInfo == null) return; // need more bytes for length
      final headerBytes = 1 + lenInfo.consumed;
      final remaining = lenInfo.value;
      if (view.length < headerBytes + remaining) return;
      final body = view.sublist(headerBytes, headerBytes + remaining);
      _packets.add(MqttPacket((header >> 4) & 0x0f, header & 0x0f, body));
      final tail = view.sublist(headerBytes + remaining);
      _buf
        ..clear()
        ..add(tail);
    }
  }
}

abstract class _MqttBase implements ApplicationProtocol {
  @override
  final String alpn = mqttAlpn;
  final QuicConnection conn;
  final Completer<MqttOverQuicConnection> _mqtt =
      Completer<MqttOverQuicConnection>();

  _MqttBase(this.conn);

  /// Completes once the MQTT bidi stream is bound.
  Future<MqttOverQuicConnection> get opened => _mqtt.future;

  @override
  Future<void> stop() async {
    if (_mqtt.isCompleted) {
      final c = await _mqtt.future;
      await c.close();
    }
  }
}

class MqttOverQuicServerProtocol extends _MqttBase {
  StreamSubscription<QuicStream>? _sub;
  MqttOverQuicServerProtocol(super.conn);

  @override
  Future<void> start() async {
    _sub = conn.incomingStreams.listen((s) {
      // Take the first inbound *bidi* stream as the MQTT stream.
      final isUni = (s.id & 0x02) != 0;
      if (isUni) return;
      if (_mqtt.isCompleted) return;
      print('✅ [mqtt] accepted stream id=${s.id}');
      _mqtt.complete(MqttOverQuicConnection._(s));
    });
  }

  @override
  Future<void> stop() async {
    await _sub?.cancel();
    await super.stop();
  }
}

class MqttOverQuicClientProtocol extends _MqttBase {
  MqttOverQuicClientProtocol(super.conn);

  @override
  Future<void> start() async {
    final s = await conn.openBidirectionalStream();
    print('🚀 [mqtt] opened stream id=${s.id}');
    _mqtt.complete(MqttOverQuicConnection._(s));
  }
}

class MqttOverQuicProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [mqttAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      MqttOverQuicServerProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      MqttOverQuicClientProtocol(conn);
}
