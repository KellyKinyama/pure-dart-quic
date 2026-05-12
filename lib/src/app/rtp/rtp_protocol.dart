// RTP-over-QUIC (RoQ) — research-grade demo module loosely inspired
// by `draft-ietf-avtcore-rtp-over-quic`. Carries RTP packets over a
// QUIC connection using two transport options:
//
//   * DATAGRAM (RFC 9221): low-latency, unreliable; payload =
//       varint(flow_id) || RTP packet
//   * Unidirectional QUIC stream per flow: reliable, ordered;
//       repeated [ varint(rtp_packet_len) || RTP packet ], the
//       sender FINs the stream when the flow ends.
//
// The wire format is intentionally minimal — there is *no* control
// stream / SETUP exchange. A `flow_id` is just an opaque varint
// chosen by the sender (typically one per SSRC); the receiver routes
// inbound packets by `flow_id` and exposes them as
// [IncomingRtpPacket] events tagged with their transport.
//
// API:
//   * [RtpPacket]                      — value type for one RTP packet
//   * [encodeRtpPacket] / [decodeRtpPacket]
//   * [RtpOverQuicProtocol]            — symmetric peer (server/client);
//                                        `sendDatagram(flowId, packet)`,
//                                        `sendStream(flowId, packets)`,
//                                        `incoming` stream.
//   * [RtpOverQuicProtocolFactory]
//
// ALPN: `roq-09` (provisional in this repo).

import 'dart:async';
import 'dart:typed_data';

import '../../../utils.dart';
import '../../transport/quic/quic_connection.dart';
import '../application_protocol.dart';

/// ALPN string for RTP-over-QUIC in this repo.
const String roqAlpn = 'roq-09';

/// How an inbound RTP packet was delivered.
enum RtpTransport {
  /// QUIC DATAGRAM (RFC 9221) — unreliable, MTU-bounded.
  datagram,

  /// Unidirectional QUIC stream — reliable, ordered.
  stream,
}

/// Decoded RTP packet (RFC 3550 §5.1).
///
/// Only the fixed 12-byte header is modelled directly. CSRC list and
/// header extensions are preserved opaquely so packets can be
/// round-tripped without loss.
class RtpPacket {
  /// Marker bit.
  final bool marker;

  /// 7-bit payload type.
  final int payloadType;

  /// 16-bit sequence number.
  final int sequenceNumber;

  /// 32-bit timestamp.
  final int timestamp;

  /// 32-bit SSRC.
  final int ssrc;

  /// Zero or more 32-bit CSRC identifiers.
  final List<int> csrcs;

  /// Header extension bytes (including the 4-byte profile+length
  /// prefix as it appears on the wire), or empty if X=0.
  final Uint8List extension;

  /// Payload bytes (after any RFC 3550 padding has been stripped).
  final Uint8List payload;

  RtpPacket({
    required this.marker,
    required this.payloadType,
    required this.sequenceNumber,
    required this.timestamp,
    required this.ssrc,
    required this.payload,
    List<int>? csrcs,
    Uint8List? extension,
  }) : csrcs = csrcs ?? const <int>[],
       extension = extension ?? _emptyBytes;

  @override
  String toString() =>
      'RtpPacket(pt=$payloadType seq=$sequenceNumber ts=$timestamp '
      'ssrc=0x${ssrc.toRadixString(16)} m=$marker '
      'csrc=${csrcs.length} x=${extension.length} '
      'len=${payload.length})';
}

final Uint8List _emptyBytes = Uint8List(0);

/// Encode an [RtpPacket] to RFC 3550 wire format (no padding).
Uint8List encodeRtpPacket(RtpPacket p) {
  if (p.payloadType < 0 || p.payloadType > 0x7f) {
    throw ArgumentError('payloadType out of range: ${p.payloadType}');
  }
  if (p.sequenceNumber < 0 || p.sequenceNumber > 0xffff) {
    throw ArgumentError('sequenceNumber out of range: ${p.sequenceNumber}');
  }
  if (p.csrcs.length > 15) {
    throw ArgumentError('too many CSRCs: ${p.csrcs.length}');
  }
  final hasExt = p.extension.isNotEmpty;
  final headerLen = 12 + 4 * p.csrcs.length + p.extension.length;
  final out = Uint8List(headerLen + p.payload.length);
  out[0] = (2 << 6) | (hasExt ? 0x10 : 0) | (p.csrcs.length & 0x0f);
  out[1] = (p.marker ? 0x80 : 0) | (p.payloadType & 0x7f);
  final bd = ByteData.view(out.buffer);
  bd.setUint16(2, p.sequenceNumber, Endian.big);
  bd.setUint32(4, p.timestamp & 0xffffffff, Endian.big);
  bd.setUint32(8, p.ssrc & 0xffffffff, Endian.big);
  var off = 12;
  for (final c in p.csrcs) {
    bd.setUint32(off, c & 0xffffffff, Endian.big);
    off += 4;
  }
  if (hasExt) {
    out.setRange(off, off + p.extension.length, p.extension);
    off += p.extension.length;
  }
  out.setRange(off, off + p.payload.length, p.payload);
  return out;
}

/// Decode an RTP packet from [data], or return `null` if it is
/// malformed / truncated.
RtpPacket? decodeRtpPacket(Uint8List data) {
  if (data.length < 12) return null;
  final b0 = data[0];
  final version = b0 >> 6;
  if (version != 2) return null;
  final padding = (b0 & 0x20) != 0;
  final hasExt = (b0 & 0x10) != 0;
  final cc = b0 & 0x0f;
  final b1 = data[1];
  final marker = (b1 & 0x80) != 0;
  final pt = b1 & 0x7f;
  final bd = ByteData.view(data.buffer, data.offsetInBytes, data.length);
  final seq = bd.getUint16(2, Endian.big);
  final ts = bd.getUint32(4, Endian.big);
  final ssrc = bd.getUint32(8, Endian.big);
  var off = 12;
  if (off + 4 * cc > data.length) return null;
  final csrcs = <int>[];
  for (var i = 0; i < cc; i++) {
    csrcs.add(bd.getUint32(off, Endian.big));
    off += 4;
  }
  Uint8List ext = _emptyBytes;
  if (hasExt) {
    if (off + 4 > data.length) return null;
    final extLen = bd.getUint16(off + 2, Endian.big);
    final extTotal = 4 + 4 * extLen;
    if (off + extTotal > data.length) return null;
    ext = Uint8List.sublistView(data, off, off + extTotal);
    off += extTotal;
  }
  var end = data.length;
  if (padding) {
    if (end <= off) return null;
    final padLen = data[end - 1];
    if (padLen == 0 || end - off < padLen) return null;
    end -= padLen;
  }
  final payload = Uint8List.sublistView(data, off, end);
  return RtpPacket(
    marker: marker,
    payloadType: pt,
    sequenceNumber: seq,
    timestamp: ts,
    ssrc: ssrc,
    csrcs: csrcs,
    extension: ext,
    payload: payload,
  );
}

/// Encode a RoQ DATAGRAM payload: varint(flowId) || RTP packet.
Uint8List encodeRoqDatagram(int flowId, RtpPacket packet) {
  final f = writeVarInt(flowId);
  final rtp = encodeRtpPacket(packet);
  final out = Uint8List(f.length + rtp.length);
  out.setRange(0, f.length, f);
  out.setRange(f.length, out.length, rtp);
  return out;
}

/// Parsed `(flowId, packet)` from a RoQ DATAGRAM payload, or null.
class RoqDatagram {
  final int flowId;
  final RtpPacket packet;
  const RoqDatagram(this.flowId, this.packet);
}

RoqDatagram? decodeRoqDatagram(Uint8List data) {
  final f = readVarInt(data, 0);
  if (f == null) return null;
  final rtp = decodeRtpPacket(Uint8List.sublistView(data, f.byteLength));
  if (rtp == null) return null;
  return RoqDatagram(f.value, rtp);
}

/// An RTP packet observed on this RoQ peer.
class IncomingRtpPacket {
  final int flowId;
  final RtpPacket packet;
  final RtpTransport transport;

  /// For [RtpTransport.stream] this is the QUIC stream id the packet
  /// arrived on; for DATAGRAM it is `null`.
  final int? streamId;

  const IncomingRtpPacket({
    required this.flowId,
    required this.packet,
    required this.transport,
    this.streamId,
  });

  @override
  String toString() =>
      'IncomingRtpPacket(flow=$flowId via=$transport '
      'stream=$streamId $packet)';
}

/// Symmetric RoQ peer. Both endpoints (server / client) behave the
/// same: they can send RTP via [sendDatagram] or [sendStream], and
/// they observe inbound RTP via [incoming].
class RtpOverQuicProtocol implements ApplicationProtocol {
  @override
  final String alpn = roqAlpn;
  final QuicConnection conn;

  StreamSubscription<QuicStream>? _streamSub;
  StreamSubscription<Uint8List>? _datagramSub;

  final StreamController<IncomingRtpPacket> _incoming =
      StreamController<IncomingRtpPacket>.broadcast();

  /// Inbound RTP packets, regardless of how they were transported.
  Stream<IncomingRtpPacket> get incoming => _incoming.stream;

  RtpOverQuicProtocol(this.conn) {
    // Subscribe immediately so we don't miss broadcast events that
    // arrive between handshake completion and `start()` being
    // scheduled by the endpoint.
    _datagramSub = conn.datagrams.listen(_onDatagram);
    _streamSub = conn.incomingStreams.listen(_onIncomingStream);
  }

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {
    await _datagramSub?.cancel();
    await _streamSub?.cancel();
    if (!_incoming.isClosed) await _incoming.close();
  }

  /// Send a single [packet] on `flowId` as a QUIC DATAGRAM.
  void sendDatagram(int flowId, RtpPacket packet) {
    conn.sendDatagram(encodeRoqDatagram(flowId, packet));
  }

  /// Open a fresh unidirectional QUIC stream and write each packet
  /// length-prefixed with a varint. The stream is FINed after the
  /// last packet. Returns the [QuicStream] used (already closed).
  Future<QuicStream> sendStream(int flowId, List<RtpPacket> packets) async {
    final s = await conn.openUnidirectionalStream();
    // Leading varint(flow_id) once per stream.
    s.write(writeVarInt(flowId));
    for (final p in packets) {
      final rtp = encodeRtpPacket(p);
      final lp = writeVarInt(rtp.length);
      final out = Uint8List(lp.length + rtp.length);
      out.setRange(0, lp.length, lp);
      out.setRange(lp.length, out.length, rtp);
      s.write(out);
    }
    await s.close();
    return s;
  }

  void _onDatagram(Uint8List data) {
    final d = decodeRoqDatagram(data);
    if (d == null) return;
    if (_incoming.isClosed) return;
    _incoming.add(
      IncomingRtpPacket(
        flowId: d.flowId,
        packet: d.packet,
        transport: RtpTransport.datagram,
      ),
    );
  }

  void _onIncomingStream(QuicStream s) {
    final isUni = (s.id & 0x02) != 0;
    if (!isUni) return;
    _drainStream(s);
  }

  Future<void> _drainStream(QuicStream s) async {
    final buf = BytesBuilder(copy: false);
    int? flowId;
    try {
      await for (final chunk in s.incoming) {
        buf.add(chunk);
        // Consume the leading varint flow_id once, as soon as enough
        // bytes are buffered.
        if (flowId == null) {
          final view = buf.toBytes();
          final f = readVarInt(view, 0);
          if (f == null) continue;
          flowId = f.value;
          final tail = Uint8List.sublistView(view, f.byteLength);
          buf
            ..clear()
            ..add(tail);
        }
        // Try to consume as many length-prefixed packets as available.
        while (true) {
          final view = buf.toBytes();
          if (view.isEmpty) break;
          final lp = readVarInt(view, 0);
          if (lp == null) break;
          if (view.length < lp.byteLength + lp.value) break;
          final rtpBytes = Uint8List.sublistView(
            view,
            lp.byteLength,
            lp.byteLength + lp.value,
          );
          final pkt = decodeRtpPacket(rtpBytes);
          if (pkt != null && !_incoming.isClosed) {
            _incoming.add(
              IncomingRtpPacket(
                flowId: flowId,
                packet: pkt,
                transport: RtpTransport.stream,
                streamId: s.id,
              ),
            );
          }
          final tail = Uint8List.sublistView(view, lp.byteLength + lp.value);
          buf
            ..clear()
            ..add(tail);
        }
      }
    } catch (e) {
      // Stream aborted mid-flow — surface as a log only; remaining
      // buffered bytes are discarded.
      // ignore: avoid_print
      print('🛑 [roq] uni stream id=${s.id} aborted: $e');
    }
  }
}

class RtpOverQuicProtocolFactory implements ApplicationProtocolFactory {
  @override
  List<String> get alpnIds => const [roqAlpn];

  @override
  ApplicationProtocol createServer(QuicConnection conn) =>
      RtpOverQuicProtocol(conn);

  @override
  ApplicationProtocol createClient(QuicConnection conn) =>
      RtpOverQuicProtocol(conn);
}
