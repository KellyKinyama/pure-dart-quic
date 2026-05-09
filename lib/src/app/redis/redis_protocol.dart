// Redis-over-QUIC.
//
// Wire format:
//   * One bidirectional QUIC stream per Redis session.
//   * On the stream, RESP2 framing is used verbatim
//     (https://redis.io/docs/latest/develop/reference/protocol-spec/).
//     This means commands are sent as RESP arrays of bulk strings
//     (`*N\r\n$len\r\nbytes\r\n…`) and responses follow RESP types
//     `+`, `-`, `:`, `$`, `*`.
//
// API:
//   * `RedisOverQuicConnection.values` — inbound stream of decoded
//     `RedisValue`s.
//   * `RedisOverQuicConnection.send(RedisValue v)` — encode + write.
//   * `RedisOverQuicConnection.command(List<dynamic> args)` —
//     convenience for sending an array of bulk-string arguments.
//
// ALPN: `redis`.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String redisAlpn = 'redis';

/// One RESP value. The `kind` field uses the RESP type byte:
///   `+` simple string, `-` error, `:` integer, `$` bulk string,
///   `*` array. A null bulk/array is signaled with `value == null`.
class RedisValue {
  final int kind;
  final dynamic value;
  RedisValue(this.kind, this.value);

  RedisValue.simpleString(String s) : this(0x2b, s);
  RedisValue.error(String s) : this(0x2d, s);
  RedisValue.integer(int n) : this(0x3a, n);
  RedisValue.bulkString(Uint8List bytes) : this(0x24, bytes);
  RedisValue.nullBulk() : this(0x24, null);
  RedisValue.array(List<RedisValue> items) : this(0x2a, items);
  RedisValue.nullArray() : this(0x2a, null);

  @override
  String toString() {
    final c = String.fromCharCode(kind);
    if (value is Uint8List) {
      try {
        return 'RedisValue($c "${utf8.decode(value as Uint8List)}")';
      } on FormatException {
        return 'RedisValue($c <${(value as Uint8List).length} bytes>)';
      }
    }
    return 'RedisValue($c $value)';
  }
}

/// Encode a list of command arguments (Strings or Uint8Lists) as a
/// RESP array of bulk strings.
Uint8List encodeRedisCommand(List<dynamic> args) {
  final out = BytesBuilder();
  out.add(utf8.encode('*${args.length}\r\n'));
  for (final a in args) {
    final bytes = a is Uint8List
        ? a
        : Uint8List.fromList(utf8.encode(a.toString()));
    out.add(utf8.encode('\$${bytes.length}\r\n'));
    out.add(bytes);
    out.add(const [0x0d, 0x0a]);
  }
  return out.toBytes();
}

/// Encode a single RedisValue (RESP2).
Uint8List encodeRedisValue(RedisValue v) {
  final out = BytesBuilder();
  _encodeInto(v, out);
  return out.toBytes();
}

void _encodeInto(RedisValue v, BytesBuilder out) {
  switch (v.kind) {
    case 0x2b: // '+'
      out.add(utf8.encode('+${v.value as String}\r\n'));
      return;
    case 0x2d: // '-'
      out.add(utf8.encode('-${v.value as String}\r\n'));
      return;
    case 0x3a: // ':'
      out.add(utf8.encode(':${v.value as int}\r\n'));
      return;
    case 0x24: // '$'
      if (v.value == null) {
        out.add(utf8.encode('\$-1\r\n'));
      } else {
        final b = v.value as Uint8List;
        out.add(utf8.encode('\$${b.length}\r\n'));
        out.add(b);
        out.add(const [0x0d, 0x0a]);
      }
      return;
    case 0x2a: // '*'
      if (v.value == null) {
        out.add(utf8.encode('*-1\r\n'));
      } else {
        final items = v.value as List<RedisValue>;
        out.add(utf8.encode('*${items.length}\r\n'));
        for (final item in items) {
          _encodeInto(item, out);
        }
      }
      return;
    default:
      throw StateError('Unknown RESP kind 0x${v.kind.toRadixString(16)}');
  }
}

/// Find the offset of the next CRLF starting at [from] in [data], or
/// -1 if not present.
int _indexOfCrlf(Uint8List data, int from) {
  for (var i = from; i + 1 < data.length; i++) {
    if (data[i] == 0x0d && data[i + 1] == 0x0a) return i;
  }
  return -1;
}

/// Try to decode one RESP value starting at [from]. Returns the value
/// and the number of bytes consumed, or null if more data is needed.
({RedisValue value, int consumed})? _decodeOne(Uint8List data, int from) {
  if (from >= data.length) return null;
  final kind = data[from];
  final crlf = _indexOfCrlf(data, from + 1);
  if (crlf < 0) return null;
  final headerStr = utf8.decode(data.sublist(from + 1, crlf));
  switch (kind) {
    case 0x2b:
      return (
        value: RedisValue.simpleString(headerStr),
        consumed: crlf + 2 - from,
      );
    case 0x2d:
      return (value: RedisValue.error(headerStr), consumed: crlf + 2 - from);
    case 0x3a:
      return (
        value: RedisValue.integer(int.parse(headerStr)),
        consumed: crlf + 2 - from,
      );
    case 0x24:
      final len = int.parse(headerStr);
      if (len < 0) {
        return (value: RedisValue.nullBulk(), consumed: crlf + 2 - from);
      }
      final bodyStart = crlf + 2;
      final bodyEnd = bodyStart + len;
      if (data.length < bodyEnd + 2) return null; // need data + trailing CRLF
      final body = data.sublist(bodyStart, bodyEnd);
      return (value: RedisValue.bulkString(body), consumed: bodyEnd + 2 - from);
    case 0x2a:
      final n = int.parse(headerStr);
      if (n < 0) {
        return (value: RedisValue.nullArray(), consumed: crlf + 2 - from);
      }
      var pos = crlf + 2;
      final items = <RedisValue>[];
      for (var i = 0; i < n; i++) {
        final inner = _decodeOne(data, pos);
        if (inner == null) return null;
        items.add(inner.value);
        pos += inner.consumed;
      }
      return (value: RedisValue.array(items), consumed: pos - from);
    default:
      throw FormatException(
        'Unknown RESP kind byte 0x${kind.toRadixString(16)}',
      );
  }
}

/// Logical Redis-over-QUIC session multiplexed onto one bidi stream.
class RedisOverQuicConnection {
  final QuicStream stream;
  final StreamController<RedisValue> _values = StreamController<RedisValue>();

  final BytesBuilder _buf = BytesBuilder();
  StreamSubscription<Uint8List>? _sub;

  RedisOverQuicConnection._(this.stream) {
    _sub = stream.incoming.listen(
      _onChunk,
      onDone: () {
        if (!_values.isClosed) _values.close();
      },
    );
  }

  /// Inbound RESP values.
  Stream<RedisValue> get values => _values.stream;

  /// Send a pre-built RESP value.
  void send(RedisValue v) => stream.write(encodeRedisValue(v));

  /// Send a command as `*N\r\n$len\r\nbytes\r\n…`.
  void command(List<dynamic> args) => stream.write(encodeRedisCommand(args));

  Future<void> close() async {
    await _sub?.cancel();
    if (!_values.isClosed) await _values.close();
    await stream.close();
  }

  void _onChunk(Uint8List chunk) {
    _buf.add(chunk);
    while (true) {
      final view = _buf.toBytes();
      if (view.isEmpty) return;
      final decoded = _decodeOne(view, 0);
      if (decoded == null) return;
      _values.add(decoded.value);
      final tail = view.sublist(decoded.consumed);
      _buf
        ..clear()
        ..add(tail);
    }
  }
}

abstract class _RedisBase implements ApplicationProtocol {
  @override
  final String alpn = redisAlpn;
  final QuicConnection conn;
  final Completer<RedisOverQuicConnection> _redis =
      Completer<RedisOverQuicConnection>();

  _RedisBase(this.conn);

  Future<RedisOverQuicConnection> get opened => _redis.future;

  @override
  Future<void> stop() async {
    if (_redis.isCompleted) {
      final c = await _redis.future;
      await c.close();
    }
  }
}

class RedisOverQuicServerProtocol extends _RedisBase {
  StreamSubscription<QuicStream>? _sub;
  RedisOverQuicServerProtocol(super.conn);

  @override
  Future<void> start() async {
    _sub = conn.incomingStreams.listen((s) {
      final isUni = (s.id & 0x02) != 0;
      if (isUni) return;
      if (_redis.isCompleted) return;
      _redis.complete(RedisOverQuicConnection._(s));
    });
  }

  @override
  Future<void> stop() async {
    await _sub?.cancel();
    await super.stop();
  }
}

class RedisOverQuicClientProtocol extends _RedisBase {
  RedisOverQuicClientProtocol(super.conn);

  @override
  Future<void> start() async {
    final s = await conn.openBidirectionalStream();
    _redis.complete(RedisOverQuicConnection._(s));
  }
}

class RedisOverQuicProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [redisAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      RedisOverQuicServerProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      RedisOverQuicClientProtocol(conn);
}
