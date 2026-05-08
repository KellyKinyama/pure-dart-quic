// Per-encryption-level sent-packet record used by loss recovery.
//
// Only Application/1-RTT level is tracked by the current wiring;
// Initial / Handshake retransmission would require additional
// frame-level retransmission of CRYPTO chunks which is out of scope
// for this research-grade engine.

import 'dart:typed_data';

/// Frame snapshot retained for retransmission. Only frame kinds that
/// the engine actually re-sends are modelled here.
abstract class RetransmittableFrame {
  const RetransmittableFrame();
}

/// A STREAM frame that may be retransmitted as-is on loss.
class StreamFrameRecord extends RetransmittableFrame {
  final int streamId;
  final int offset;
  final Uint8List data;
  final bool fin;
  const StreamFrameRecord({
    required this.streamId,
    required this.offset,
    required this.data,
    required this.fin,
  });
}

/// A PING frame placeholder. Used to elicit ACKs for PTO probes.
/// Retransmission isn't strictly required, but we remember the packet
/// so it shows up in bytes-in-flight / ACK accounting.
class PingFrameRecord extends RetransmittableFrame {
  const PingFrameRecord();
}

/// A snapshot of a sent application-level packet.
class SentPacket {
  /// Packet number assigned at send time.
  final int pn;

  /// Wall-clock time the packet went on the wire.
  final DateTime sentTime;

  /// Total UDP payload size, in bytes — used for congestion control
  /// (`bytes_in_flight`).
  final int sizeInBytes;

  /// True if the packet contains at least one ack-eliciting frame
  /// (anything other than ACK / PADDING / CONNECTION_CLOSE).
  final bool ackEliciting;

  /// True if the packet counts toward congestion control. Equal to
  /// `ackEliciting` for our purposes (CC excludes pure-ACK packets).
  final bool inFlight;

  /// Frames eligible for retransmission on loss. Empty for pure ACK
  /// packets and DATAGRAM-only packets (DATAGRAMs are not retransmitted
  /// per RFC 9221).
  final List<RetransmittableFrame> frames;

  SentPacket({
    required this.pn,
    required this.sentTime,
    required this.sizeInBytes,
    required this.ackEliciting,
    required this.inFlight,
    this.frames = const <RetransmittableFrame>[],
  });
}
