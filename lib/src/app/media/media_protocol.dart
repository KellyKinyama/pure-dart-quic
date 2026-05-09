// Media-over-QUIC (MoQ) — research-grade demo module loosely inspired
// by draft-ietf-moq-transport. NOT wire-compatible with the IETF
// draft; this implements just enough to drive realistic one-to-many
// and many-to-many media fan-out on top of [QuicConnection].
//
// Wire format
// -----------
// One bidirectional QUIC stream per peer carries control messages
// (length-prefixed with a varint type and varint length):
//
//   SETUP        (0x01)  client -> server  body = utf8(role)
//   SETUP_OK     (0x02)  server -> client  body = ""
//   SUBSCRIBE    (0x03)  client -> server  body = utf8(track)
//   ANNOUNCE     (0x04)  server -> client  body = utf8(track)
//   UNSUBSCRIBE  (0x05)  client -> server  body = utf8(track)
//
// Media samples are sent as QUIC DATAGRAMs (RFC 9221) with header:
//
//   varint(track_name_len) || track_name_utf8 ||
//   varint(group_id) || varint(object_id) || payload
//
// Carrying the track *name* (rather than a negotiated id) on every
// datagram keeps fan-out routing trivial: the [MoqBroker] reads the
// name out of each inbound datagram and forwards to every connection
// that has SUBSCRIBEd to it.
//
// API
// ---
// * [MoqObject]                       — value type for one media sample.
// * [MediaOverQuicClientProtocol]     — `subscribe()`, `publish()`, `objects`.
// * [MediaOverQuicServerProtocol]     — per-connection server side; emits
//                                       `subscribes` / `unsubscribes` and
//                                       its own `objects` stream. Can be
//                                       attached to a [MoqBroker] for
//                                       fan-out.
// * [MoqBroker]                       — track-keyed pub/sub broker that
//                                       wires multiple per-connection
//                                       server protocols together.
// * [MoqBrokerProtocolFactory]        — drop-in factory that creates
//                                       broker-attached server protocols.
//
// ALPN: `moq-00` (provisional in this repo, not the IETF value).

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../../../utils.dart';
import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

const String moqAlpn = 'moq-00';

const int moqCtrlSetup = 0x01;
const int moqCtrlSetupOk = 0x02;
const int moqCtrlSubscribe = 0x03;
const int moqCtrlAnnounce = 0x04;
const int moqCtrlUnsubscribe = 0x05;

/// One media object delivered as a single QUIC DATAGRAM.
class MoqObject {
  /// Track name (full namespace + track, opaque to this layer).
  final String track;

  /// Group id (e.g. GoP / segment number).
  final int groupId;

  /// Object id within the group (e.g. frame index).
  final int objectId;

  /// Opaque media bytes.
  final Uint8List payload;

  const MoqObject({
    required this.track,
    required this.groupId,
    required this.objectId,
    required this.payload,
  });

  @override
  String toString() =>
      'MoqObject(track=$track group=$groupId obj=$objectId '
      'len=${payload.length})';
}

/// Encode a control message (varint type || varint len || body).
Uint8List encodeMoqControl(int type, Uint8List body) {
  final t = writeVarInt(type);
  final l = writeVarInt(body.length);
  final out = Uint8List(t.length + l.length + body.length);
  out.setRange(0, t.length, t);
  out.setRange(t.length, t.length + l.length, l);
  out.setRange(t.length + l.length, out.length, body);
  return out;
}

/// Encode a media object DATAGRAM payload.
Uint8List encodeMoqObjectDatagram(MoqObject obj) {
  final name = utf8.encode(obj.track);
  final nLen = writeVarInt(name.length);
  final g = writeVarInt(obj.groupId);
  final o = writeVarInt(obj.objectId);
  final out = Uint8List(
    nLen.length + name.length + g.length + o.length + obj.payload.length,
  );
  var off = 0;
  out.setRange(off, off += nLen.length, nLen);
  out.setRange(off, off += name.length, name);
  out.setRange(off, off += g.length, g);
  out.setRange(off, off += o.length, o);
  out.setRange(off, off + obj.payload.length, obj.payload);
  return out;
}

MoqObject? decodeMoqObjectDatagram(Uint8List data) {
  var off = 0;
  final nLen = readVarInt(data, off);
  if (nLen == null) return null;
  off += nLen.byteLength;
  if (off + nLen.value > data.length) return null;
  final track = utf8.decode(data.sublist(off, off + nLen.value));
  off += nLen.value;
  final g = readVarInt(data, off);
  if (g == null) return null;
  off += g.byteLength;
  final o = readVarInt(data, off);
  if (o == null) return null;
  off += o.byteLength;
  return MoqObject(
    track: track,
    groupId: g.value,
    objectId: o.value,
    payload: Uint8List.sublistView(data, off),
  );
}

class MoqCtrlMsg {
  final int type;
  final Uint8List body;
  const MoqCtrlMsg(this.type, this.body);
}

abstract class MediaOverQuicBase implements ApplicationProtocol {
  @override
  final String alpn = moqAlpn;
  final QuicConnection conn;

  QuicStream? _ctrl;
  final BytesBuilder _ctrlBuf = BytesBuilder();

  StreamSubscription<QuicStream>? _streamSub;
  StreamSubscription<Uint8List>? _datagramSub;
  StreamSubscription<Uint8List>? _ctrlSub;

  final StreamController<MoqObject> _objectsCtrl =
      StreamController<MoqObject>.broadcast();

  /// Inbound media objects (DATAGRAM-delivered).
  Stream<MoqObject> get objects => _objectsCtrl.stream;

  MediaOverQuicBase(this.conn);

  @override
  Future<void> start() async {
    _streamSub = conn.incomingStreams.listen(_onPeerStream);
    _datagramSub = conn.datagrams.listen(_onDatagram);
    await onStarted();
  }

  Future<void> onStarted() async {}

  @override
  Future<void> stop() async {
    await _streamSub?.cancel();
    await _datagramSub?.cancel();
    await _ctrlSub?.cancel();
    if (!_objectsCtrl.isClosed) await _objectsCtrl.close();
  }

  void _onPeerStream(QuicStream s) {
    final isUni = (s.id & 0x02) != 0;
    if (isUni) {
      // Reliable object delivery: every inbound uni stream carries
      // exactly one MoqObject (encoded with the same wire format as the
      // DATAGRAM payload), terminated by FIN.
      _drainObjectStream(s);
      return;
    }
    if (_ctrl != null) return;
    _ctrl = s;
    _ctrlSub = s.incoming.listen(_onCtrlChunk);
    print('✅ [moq] bound control stream id=${s.id}');
    onCtrlBound();
  }

  Future<void> _drainObjectStream(QuicStream s) async {
    final b = BytesBuilder(copy: false);
    try {
      await for (final chunk in s.incoming) {
        b.add(chunk);
      }
    } catch (e) {
      print('🛑 [moq] reliable stream id=${s.id} aborted: $e');
      return;
    }
    final raw = b.toBytes();
    final obj = decodeMoqObjectDatagram(raw);
    if (obj == null) {
      print('🛑 [moq] reliable stream id=${s.id} payload undecodable');
      return;
    }
    print('📦 [moq] STREAM object stream=${s.id} $obj');
    onObject(obj);
  }

  void onCtrlBound() {}

  void _onCtrlChunk(Uint8List chunk) {
    _ctrlBuf.add(chunk);
    while (true) {
      final view = _ctrlBuf.toBytes();
      if (view.isEmpty) return;
      final t = readVarInt(view, 0);
      if (t == null) return;
      final l = readVarInt(view, t.byteLength);
      if (l == null) return;
      final headerLen = t.byteLength + l.byteLength;
      if (view.length < headerLen + l.value) return;
      final body = view.sublist(headerLen, headerLen + l.value);
      onCtrlMessage(MoqCtrlMsg(t.value, body));
      final tail = view.sublist(headerLen + l.value);
      _ctrlBuf
        ..clear()
        ..add(tail);
    }
  }

  void onCtrlMessage(MoqCtrlMsg msg) {}

  void sendCtrl(int type, Uint8List body) {
    final s = _ctrl;
    if (s == null) {
      throw StateError('[moq] control stream not bound');
    }
    s.write(encodeMoqControl(type, body));
  }

  /// Publish a media object as a QUIC DATAGRAM on this connection.
  /// Low-latency, lossy, MTU-bounded (~1200 bytes payload).
  void publish(MoqObject obj) {
    conn.sendDatagram(encodeMoqObjectDatagram(obj));
  }

  /// Publish a media object on a fresh unidirectional QUIC stream
  /// (reliable, ordered, no MTU bound). The receiver decodes one
  /// [MoqObject] per stream once the sender FINs.
  Future<void> publishReliable(MoqObject obj) async {
    final s = await conn.openUnidirectionalStream();
    s.write(encodeMoqObjectDatagram(obj));
    await s.close();
  }

  void _onDatagram(Uint8List data) {
    final obj = decodeMoqObjectDatagram(data);
    if (obj == null) return;
    onObject(obj);
  }

  /// Hook for subclasses to intercept inbound objects (e.g. for broker
  /// fan-out) before they are emitted on [objects].
  void onObject(MoqObject obj) {
    if (!_objectsCtrl.isClosed) _objectsCtrl.add(obj);
  }
}

class MediaOverQuicServerProtocol extends MediaOverQuicBase {
  final StreamController<String> _subscribesCtrl =
      StreamController<String>.broadcast();
  final StreamController<String> _unsubscribesCtrl =
      StreamController<String>.broadcast();

  /// Track names this peer (client) has subscribed to.
  Stream<String> get subscribes => _subscribesCtrl.stream;

  /// Track names this peer has unsubscribed from.
  Stream<String> get unsubscribes => _unsubscribesCtrl.stream;

  /// Optional broker; when set, inbound DATAGRAMs are also forwarded
  /// to other connections subscribed to the same track via the broker
  /// (see [MoqBroker]).
  MoqBroker? broker;

  /// Track names this connection is currently subscribed to. Owned
  /// by the broker; do not mutate directly.
  final Set<String> activeSubscriptions = <String>{};

  MediaOverQuicServerProtocol(super.conn, {this.broker});

  @override
  void onCtrlMessage(MoqCtrlMsg msg) {
    switch (msg.type) {
      case moqCtrlSetup:
        final role = utf8.decode(msg.body);
        print('✅ [moq] SETUP role=$role');
        sendCtrl(moqCtrlSetupOk, Uint8List(0));
        break;
      case moqCtrlSubscribe:
        final track = utf8.decode(msg.body);
        print('✅ [moq] SUBSCRIBE track=$track');
        broker?.subscribe(this, track);
        _subscribesCtrl.add(track);
        // Acknowledge with an ANNOUNCE for the same track name.
        sendCtrl(moqCtrlAnnounce, Uint8List.fromList(utf8.encode(track)));
        break;
      case moqCtrlAnnounce:
        final track = utf8.decode(msg.body);
        print('✅ [moq] ANNOUNCE (from publisher) track=$track');
        broker?.announceTrack(this, track);
        break;
      case moqCtrlUnsubscribe:
        final track = utf8.decode(msg.body);
        print('✅ [moq] UNSUBSCRIBE track=$track');
        broker?.unsubscribe(this, track);
        _unsubscribesCtrl.add(track);
        break;
      default:
        print(
          'ℹ️ [moq] server ignored ctrl type=0x'
          '${msg.type.toRadixString(16)}',
        );
    }
  }

  @override
  void onObject(MoqObject obj) {
    super.onObject(obj);
    // Fan out via the broker if attached.
    broker?.dispatch(this, obj);
  }

  /// Send an ANNOUNCE control message to this peer. Used by the
  /// broker to relay a publisher's ANNOUNCE to other connections.
  void sendAnnounce(String track) {
    sendCtrl(moqCtrlAnnounce, Uint8List.fromList(utf8.encode(track)));
  }

  @override
  Future<void> stop() async {
    broker?.detach(this);
    if (!_subscribesCtrl.isClosed) await _subscribesCtrl.close();
    if (!_unsubscribesCtrl.isClosed) await _unsubscribesCtrl.close();
    await super.stop();
  }
}

class MediaOverQuicClientProtocol extends MediaOverQuicBase {
  String role;
  final Completer<void> _setupOk = Completer<void>();
  final StreamController<String> _announcesCtrl =
      StreamController<String>.broadcast();

  /// Track names announced by the server.
  Stream<String> get announces => _announcesCtrl.stream;

  /// Completes when the server replies SETUP_OK.
  Future<void> get setupCompleted => _setupOk.future;

  MediaOverQuicClientProtocol(super.conn, {this.role = 'subscriber'});

  @override
  Future<void> onStarted() async {
    final s = await conn.openBidirectionalStream();
    _ctrl = s;
    _ctrlSub = s.incoming.listen(_onCtrlChunk);
    print('🚀 [moq] opened control stream id=${s.id}');
    sendCtrl(moqCtrlSetup, Uint8List.fromList(utf8.encode(role)));
  }

  void subscribe(String track) {
    sendCtrl(moqCtrlSubscribe, Uint8List.fromList(utf8.encode(track)));
    print('🚀 [moq] sent SUBSCRIBE track=$track');
  }

  void unsubscribe(String track) {
    sendCtrl(moqCtrlUnsubscribe, Uint8List.fromList(utf8.encode(track)));
    print('🚀 [moq] sent UNSUBSCRIBE track=$track');
  }

  /// Announce that this client is the publisher for [track]. The
  /// server (broker) will relay this ANNOUNCE to other connected
  /// peers so subscribers can discover available tracks.
  void announce(String track) {
    sendCtrl(moqCtrlAnnounce, Uint8List.fromList(utf8.encode(track)));
    print('🚀 [moq] sent ANNOUNCE track=$track');
  }

  @override
  void onCtrlMessage(MoqCtrlMsg msg) {
    switch (msg.type) {
      case moqCtrlSetupOk:
        print('✅ [moq] SETUP_OK');
        if (!_setupOk.isCompleted) _setupOk.complete();
        break;
      case moqCtrlAnnounce:
        final track = utf8.decode(msg.body);
        print('✅ [moq] ANNOUNCE track=$track');
        _announcesCtrl.add(track);
        break;
      default:
        print(
          'ℹ️ [moq] client ignored ctrl type=0x'
          '${msg.type.toRadixString(16)}',
        );
    }
  }

  @override
  Future<void> stop() async {
    if (!_announcesCtrl.isClosed) await _announcesCtrl.close();
    await super.stop();
  }
}

class MediaOverQuicProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [moqAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      MediaOverQuicServerProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      MediaOverQuicClientProtocol(conn);
}

// ---------------------------------------------------------------------------
// Broker — track-keyed pub/sub for one-to-many and many-to-many fan-out
// ---------------------------------------------------------------------------

/// Server-side fan-out broker. Tracks which connections are subscribed
/// to which track names, and forwards every published [MoqObject] to
/// every subscribed connection except the sender.
///
/// Usage with a [QuicServerEndpoint]:
/// ```dart
/// final broker = MoqBroker();
/// final alpns = AlpnRegistry()..register(MoqBrokerProtocolFactory(broker));
/// final ep = await QuicServerEndpoint.bind(...);
/// ```
class MoqBroker {
  /// exact track name -> set of subscribed connections.
  final Map<String, Set<MediaOverQuicServerProtocol>> _subs =
      <String, Set<MediaOverQuicServerProtocol>>{};

  /// prefix subscriptions: prefix (without trailing '*') -> connections.
  /// A subscribe to `"video/*"` registers `"video/"` here and matches
  /// every track whose name starts with that prefix.
  final Map<String, Set<MediaOverQuicServerProtocol>> _prefixSubs =
      <String, Set<MediaOverQuicServerProtocol>>{};

  /// track -> ring buffer of recently published objects (oldest first).
  /// Used to catch up new subscribers via reliable streams.
  final Map<String, List<MoqObject>> _cache = <String, List<MoqObject>>{};

  /// All track names that have been ANNOUNCEd by some publisher (and
  /// are still attached). Maps to the announcing publisher connection.
  final Map<String, MediaOverQuicServerProtocol> _announced =
      <String, MediaOverQuicServerProtocol>{};

  /// If true (default), an inbound object from a publisher that is
  /// itself subscribed to the same track is *not* echoed back to it.
  /// Set to false to enable loopback (rarely useful).
  bool dropEcho;

  /// Number of recent objects retained per track for catch-up. Set to
  /// 0 to disable caching.
  int cacheSize;

  /// Optional callback fired for every fan-out attempt — useful for
  /// metrics or tests.
  void Function(MoqObject obj, int delivered)? onDelivered;

  /// Aggregate counters across the lifetime of the broker.
  final MoqBrokerStats stats = MoqBrokerStats();

  MoqBroker({this.dropEcho = true, this.cacheSize = 0});

  /// Number of distinct exact-track names that currently have at
  /// least one subscriber. Prefix subscriptions are not counted here
  /// (they don't bind to a single track name).
  int get trackCount => _subs.length;

  /// Number of subscribers currently registered for [track], counting
  /// both exact subscriptions and prefix subscriptions whose prefix
  /// matches [track].
  int subscriberCount(String track) {
    var n = _subs[track]?.length ?? 0;
    if (_prefixSubs.isNotEmpty) {
      _prefixSubs.forEach((prefix, set) {
        if (track.startsWith(prefix)) n += set.length;
      });
    }
    return n;
  }

  /// All exact track names that currently have at least one subscriber.
  Iterable<String> get tracks => _subs.keys;

  /// All prefix subscriptions currently registered (each as the
  /// `prefix*` form the client used to subscribe).
  Iterable<String> get prefixSubscriptions =>
      _prefixSubs.keys.map((p) => '$p*');

  /// All track names that have been ANNOUNCEd by an attached publisher.
  Iterable<String> get announcedTracks => _announced.keys;

  /// Register a publisher [from] as the announcer for [track]. Relays
  /// the ANNOUNCE to every other attached connection.
  void announceTrack(MediaOverQuicServerProtocol from, String track) {
    _announced[track] = from;
    // Relay ANNOUNCE to every other connection we know about (any
    // that has a subscription is reachable via _subs; others are not
    // yet enrolled — they'll see ANNOUNCE on their first SUBSCRIBE).
    final seen = <MediaOverQuicServerProtocol>{from};
    for (final set in _subs.values) {
      for (final s in set) {
        if (seen.add(s)) {
          try {
            s.sendAnnounce(track);
          } catch (e) {
            print('🛑 [moq.broker] ANNOUNCE relay failed: $e');
          }
        }
      }
    }
  }

  /// Register [conn] as a subscriber to [track]. The track name may
  /// end with a `*` to subscribe to every track sharing the prefix
  /// (e.g. `"video/*"` matches `"video/cam-A"` and `"video/cam-B"`).
  /// If [cacheSize] > 0 any cached recent objects on already-known
  /// matching tracks are immediately replayed to [conn] via reliable
  /// unidirectional streams.
  void subscribe(MediaOverQuicServerProtocol conn, String track) {
    if (track.endsWith('*')) {
      final prefix = track.substring(0, track.length - 1);
      _prefixSubs
          .putIfAbsent(prefix, () => <MediaOverQuicServerProtocol>{})
          .add(conn);
      conn.activeSubscriptions.add(track);
      // Replay any cached objects on already-known tracks that match.
      _cache.forEach((existing, list) {
        if (existing.startsWith(prefix)) {
          for (final obj in list) {
            unawaited(
              conn.publishReliable(obj).catchError((Object e) {
                print('🛑 [moq.broker] catch-up replay failed: $e');
              }),
            );
          }
        }
      });
      return;
    }
    _subs.putIfAbsent(track, () => <MediaOverQuicServerProtocol>{}).add(conn);
    conn.activeSubscriptions.add(track);
    // Replay cached objects to the new subscriber for catch-up.
    final cached = _cache[track];
    if (cached != null && cached.isNotEmpty) {
      for (final obj in cached) {
        unawaited(
          conn.publishReliable(obj).catchError((Object e) {
            print('🛑 [moq.broker] catch-up replay failed: $e');
          }),
        );
      }
    }
  }

  /// Remove [conn]'s subscription to [track]. Handles both exact and
  /// prefix subscriptions (matching by the original [track] string).
  void unsubscribe(MediaOverQuicServerProtocol conn, String track) {
    if (track.endsWith('*')) {
      final prefix = track.substring(0, track.length - 1);
      final set = _prefixSubs[prefix];
      if (set != null) {
        set.remove(conn);
        if (set.isEmpty) _prefixSubs.remove(prefix);
      }
      conn.activeSubscriptions.remove(track);
      return;
    }
    final set = _subs[track];
    if (set == null) return;
    set.remove(conn);
    conn.activeSubscriptions.remove(track);
    if (set.isEmpty) _subs.remove(track);
  }

  /// Drop every subscription / announcement held by [conn] (e.g. on
  /// disconnect).
  void detach(MediaOverQuicServerProtocol conn) {
    for (final track in List<String>.from(conn.activeSubscriptions)) {
      unsubscribe(conn, track);
    }
    _announced.removeWhere((_, c) => identical(c, conn));
  }

  /// Collect every connection currently subscribed to [track] (via
  /// either an exact match or a matching prefix subscription), in a
  /// stable iteration order.
  Set<MediaOverQuicServerProtocol> _matchingSubscribers(String track) {
    final out = <MediaOverQuicServerProtocol>{};
    final exact = _subs[track];
    if (exact != null) out.addAll(exact);
    if (_prefixSubs.isNotEmpty) {
      _prefixSubs.forEach((prefix, set) {
        if (track.startsWith(prefix)) out.addAll(set);
      });
    }
    return out;
  }

  /// Forward [obj] (received from [from]) to every subscriber of
  /// `obj.track`. Returns the number of recipients.
  int dispatch(MediaOverQuicServerProtocol from, MoqObject obj) {
    _cacheObject(obj);
    stats.published++;
    stats.publishedBytes += obj.payload.length;
    final subs = _matchingSubscribers(obj.track);
    if (subs.isEmpty) {
      onDelivered?.call(obj, 0);
      return 0;
    }
    var n = 0;
    for (final s in subs) {
      if (dropEcho && identical(s, from)) continue;
      try {
        s.publish(obj);
        n++;
      } catch (e) {
        stats.deliveryErrors++;
        print('🛑 [moq.broker] forward failed: $e');
      }
    }
    stats.delivered += n;
    stats.deliveredBytes += n * obj.payload.length;
    onDelivered?.call(obj, n);
    return n;
  }

  /// Reliable variant of [dispatch] — fans the object out as a
  /// dedicated unidirectional QUIC stream per subscriber. Use for
  /// keyframes or any object too large to fit a DATAGRAM.
  Future<int> dispatchReliable(
    MediaOverQuicServerProtocol from,
    MoqObject obj,
  ) async {
    _cacheObject(obj);
    stats.published++;
    stats.publishedBytes += obj.payload.length;
    final subs = _matchingSubscribers(obj.track);
    if (subs.isEmpty) {
      onDelivered?.call(obj, 0);
      return 0;
    }
    var n = 0;
    for (final s in subs) {
      if (dropEcho && identical(s, from)) continue;
      try {
        await s.publishReliable(obj);
        n++;
      } catch (e) {
        stats.deliveryErrors++;
        print('🛑 [moq.broker] reliable forward failed: $e');
      }
    }
    stats.delivered += n;
    stats.deliveredBytes += n * obj.payload.length;
    onDelivered?.call(obj, n);
    return n;
  }

  void _cacheObject(MoqObject obj) {
    if (cacheSize <= 0) return;
    final list = _cache.putIfAbsent(obj.track, () => <MoqObject>[]);
    list.add(obj);
    while (list.length > cacheSize) {
      list.removeAt(0);
    }
  }
}

/// `ApplicationProtocolFactory` that produces server-side MoQ protocols
/// pre-attached to a shared [MoqBroker]. Use this in a server endpoint
/// to get track-keyed many-to-many fan-out automatically.
class MoqBrokerProtocolFactory implements ApplicationProtocolFactory {
  final MoqBroker broker;

  MoqBrokerProtocolFactory(this.broker);

  @override
  List<String> get alpnIds => const [moqAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      MediaOverQuicServerProtocol(conn, broker: broker);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      MediaOverQuicClientProtocol(conn);
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Aggregate counters for a [MoqBroker]. Mutated in place; safe to
/// snapshot via [toString] for logging.
class MoqBrokerStats {
  /// Number of [MoqObject]s the broker has received from publishers.
  int published = 0;

  /// Sum of payload bytes across [published].
  int publishedBytes = 0;

  /// Number of times an object was successfully forwarded to a single
  /// subscriber (i.e. fan-out events). One published object can map
  /// to many delivered events.
  int delivered = 0;

  /// Sum of payload bytes across [delivered] events.
  int deliveredBytes = 0;

  /// Forward attempts that threw — typically because a subscriber's
  /// connection was already closing.
  int deliveryErrors = 0;

  /// Reset every counter back to zero.
  void reset() {
    published = 0;
    publishedBytes = 0;
    delivered = 0;
    deliveredBytes = 0;
    deliveryErrors = 0;
  }

  @override
  String toString() =>
      'MoqBrokerStats(published=$published deliveredEvents=$delivered '
      'pubBytes=$publishedBytes deliveredBytes=$deliveredBytes '
      'errors=$deliveryErrors)';
}

// ---------------------------------------------------------------------------
// High-level publisher / subscriber wrappers
// ---------------------------------------------------------------------------

/// Convenience wrapper around [MediaOverQuicClientProtocol] for the
/// publisher role. Owns one named track and an auto-incrementing
/// `(groupId, objectId)` pair so application code only needs to push
/// payload bytes.
///
/// Example:
/// ```dart
/// final pub = MoqPublisher(client, 'video/cam-A')..announce();
/// pub.send(Uint8List.fromList([1, 2, 3]));        // DATAGRAM
/// await pub.sendReliable(largeKeyframeBytes);     // uni-stream
/// pub.nextGroup();                                // bump groupId
/// ```
class MoqPublisher {
  final MediaOverQuicClientProtocol client;
  final String track;

  /// Number of objects emitted in the current group before the id
  /// rolls over (set to 0 to disable auto-rollover).
  int groupSize;

  int _groupId;
  int _objectId = 0;

  MoqPublisher(
    this.client,
    this.track, {
    this.groupSize = 0,
    int initialGroupId = 0,
  }) : _groupId = initialGroupId;

  /// Current group id.
  int get groupId => _groupId;

  /// Next object id that will be emitted within the current group.
  int get nextObjectId => _objectId;

  /// Announce this track to the broker so existing subscribers learn
  /// about it (via ANNOUNCE relay).
  void announce() => client.announce(track);

  /// Roll the group id forward and reset the object id. Call this at
  /// segment / GoP boundaries.
  void nextGroup() {
    _groupId++;
    _objectId = 0;
  }

  /// Publish [payload] as the next object via DATAGRAM (low-latency,
  /// lossy). Returns the [MoqObject] sent.
  MoqObject send(Uint8List payload) {
    final obj = _build(payload);
    client.publish(obj);
    return obj;
  }

  /// Publish [payload] as the next object via a reliable
  /// unidirectional stream. Returns the [MoqObject] sent.
  Future<MoqObject> sendReliable(Uint8List payload) async {
    final obj = _build(payload);
    await client.publishReliable(obj);
    return obj;
  }

  MoqObject _build(Uint8List payload) {
    final obj = MoqObject(
      track: track,
      groupId: _groupId,
      objectId: _objectId++,
      payload: payload,
    );
    if (groupSize > 0 && _objectId >= groupSize) {
      nextGroup();
    }
    return obj;
  }
}

/// Convenience wrapper around [MediaOverQuicClientProtocol] for the
/// subscriber role. Filters the underlying `objects` stream to objects
/// matching one track (or a `prefix*` pattern).
///
/// Example:
/// ```dart
/// final sub = await MoqSubscriber.subscribe(client, 'video/*');
/// sub.objects.listen((obj) => print('${obj.track} ${obj.payload.length}B'));
/// ```
class MoqSubscriber {
  final MediaOverQuicClientProtocol client;

  /// Track name or `prefix*` pattern this subscriber was created for.
  final String pattern;

  late final StreamSubscription<MoqObject> _sub;
  final StreamController<MoqObject> _ctrl =
      StreamController<MoqObject>.broadcast();

  bool _closed = false;

  MoqSubscriber._(this.client, this.pattern) {
    _sub = client.objects.listen((o) {
      if (_matches(o.track) && !_ctrl.isClosed) _ctrl.add(o);
    });
  }

  /// Open a subscription on [client] for [pattern] (track name or
  /// `prefix*`) and return a ready-to-use [MoqSubscriber].
  static Future<MoqSubscriber> subscribe(
    MediaOverQuicClientProtocol client,
    String pattern,
  ) async {
    final s = MoqSubscriber._(client, pattern);
    client.subscribe(pattern);
    return s;
  }

  /// Filtered stream of inbound objects matching [pattern].
  Stream<MoqObject> get objects => _ctrl.stream;

  /// Cancel this subscription and release resources. Sends an
  /// UNSUBSCRIBE for [pattern] and closes the local stream.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    try {
      client.unsubscribe(pattern);
    } catch (_) {
      /* control stream may already be gone */
    }
    await _sub.cancel();
    if (!_ctrl.isClosed) await _ctrl.close();
  }

  bool _matches(String track) {
    if (pattern.endsWith('*')) {
      return track.startsWith(pattern.substring(0, pattern.length - 1));
    }
    return track == pattern;
  }
}
