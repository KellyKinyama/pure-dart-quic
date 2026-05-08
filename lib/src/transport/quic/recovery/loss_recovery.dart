// RFC 9002 §6 loss detection for the Application packet-number space.
//
// Only the 1-RTT space is wired in; Initial/Handshake retransmission
// is left to the existing engine handshake flight code (which already
// re-sends opportunistically).

import 'dart:async';
import 'dart:math' as math;

import 'congestion_controller.dart';
import 'rtt_estimator.dart';
import 'sent_packet.dart';

/// Result of [LossRecovery.onAckReceived].
class AckProcessingResult {
  final List<SentPacket> newlyAcked;
  final List<SentPacket> newlyLost;
  AckProcessingResult({required this.newlyAcked, required this.newlyLost});
}

class LossRecovery {
  /// Packet-threshold from RFC 9002 §6.1.1.
  static const int kPacketThreshold = 3;

  /// Numerator / denominator of the time threshold (9/8).
  static const int kTimeThresholdNum = 9;
  static const int kTimeThresholdDen = 8;

  final RttEstimator rtt;
  final NewRenoController cc;

  /// Sent-packet history, ordered insertion is preserved by SplayTreeMap-like
  /// behaviour: we use a Map plus a sorted-by-PN view.
  final Map<int, SentPacket> _sent = <int, SentPacket>{};

  /// Largest packet number we have ever ACKed *to the peer* — NOT used
  /// here; recorded by upper layers if needed.

  /// Largest packet number we have observed acknowledged BY the peer.
  int? largestAckedPacket;

  /// Most recent loss-detection time (as scheduled).
  DateTime? lossDetectionTimer;

  /// Callback invoked when [onLossDetectionTimerExpired] decides to
  /// send a PTO probe. The implementation should put a single
  /// ack-eliciting frame on the wire (typically PING).
  void Function()? onPtoProbe;

  /// Callback fired when [onAckReceived] detects loss; should
  /// retransmit the contained frames as a fresh packet.
  void Function(List<SentPacket> lost)? onPacketsLost;

  int ptoCount = 0;

  LossRecovery({required this.rtt, required this.cc});

  /// Record an outgoing packet so it can later be acked / declared lost.
  void onPacketSent(SentPacket pkt) {
    _sent[pkt.pn] = pkt;
    cc.onPacketSent(pkt.sizeInBytes, inFlight: pkt.inFlight);
  }

  /// Apply an incoming ACK frame.
  ///
  /// [ackedRanges] is a list of inclusive [low, high] ranges of packet
  /// numbers acknowledged by this ACK frame. [ackDelayUs] is the
  /// `ACK_DELAY` field already converted to microseconds.
  AckProcessingResult onAckReceived({
    required int largestAcked,
    required List<(int, int)> ackedRanges,
    required int ackDelayUs,
    required bool isHandshakeConfirmed,
    DateTime? now,
  }) {
    now ??= DateTime.now();
    largestAckedPacket = largestAckedPacket == null
        ? largestAcked
        : math.max(largestAckedPacket!, largestAcked);

    final newlyAcked = <SentPacket>[];
    for (final r in ackedRanges) {
      for (var pn = r.$1; pn <= r.$2; pn++) {
        final p = _sent.remove(pn);
        if (p != null) newlyAcked.add(p);
      }
    }

    if (newlyAcked.isEmpty) {
      return AckProcessingResult(newlyAcked: const [], newlyLost: const []);
    }

    // Update RTT only from the largest-acked packet, per §5.1.
    SentPacket? largest;
    for (final p in newlyAcked) {
      if (p.pn == largestAcked) {
        largest = p;
        break;
      }
    }
    if (largest != null && largest.ackEliciting) {
      final sampleUs = now.difference(largest.sentTime).inMicroseconds;
      rtt.onRttSample(
        rttSampleUs: sampleUs,
        ackDelayUs: ackDelayUs,
        isHandshakeConfirmed: isHandshakeConfirmed,
      );
    }

    for (final p in newlyAcked) {
      cc.onPacketAcked(p.sizeInBytes, inFlight: p.inFlight, pn: p.pn);
    }

    final lost = _detectLostPackets(now);
    if (lost.isNotEmpty) {
      for (final p in lost) {
        cc.onPacketLost(p.sizeInBytes, p.pn, inFlight: p.inFlight);
      }
      onPacketsLost?.call(lost);
    }

    if (newlyAcked.isNotEmpty) {
      ptoCount = 0;
    }

    return AckProcessingResult(newlyAcked: newlyAcked, newlyLost: lost);
  }

  /// Returns packets considered lost AND removes them from the
  /// in-flight tracking map.
  List<SentPacket> _detectLostPackets(DateTime now) {
    final largest = largestAckedPacket;
    if (largest == null) return const [];

    final srtt = rtt.smoothedRttOrInitial;
    final latest = rtt.latestRtt ?? srtt;
    final timeThresholdUs =
        (math.max(srtt, latest) * kTimeThresholdNum) ~/ kTimeThresholdDen;
    final lossDelay = math.max(timeThresholdUs, RttEstimator.kGranularityUs);
    final lossTimeBound = now.subtract(Duration(microseconds: lossDelay));

    final lost = <SentPacket>[];
    final pns = _sent.keys.toList()..sort();
    for (final pn in pns) {
      if (pn >= largest) break;
      final p = _sent[pn]!;
      final sentBefore =
          p.sentTime.isBefore(lossTimeBound) ||
          p.sentTime.isAtSameMomentAs(lossTimeBound);
      final packetThresh = (largest - pn) >= kPacketThreshold;
      if (sentBefore || packetThresh) {
        lost.add(p);
      }
    }
    for (final p in lost) {
      _sent.remove(p.pn);
    }
    return lost;
  }

  /// Returns the next probe-timeout duration. Doubles on consecutive
  /// PTO firings (RFC 9002 §6.2.1).
  Duration nextPtoTimeout() {
    final base = rtt.ptoBase();
    return base * (1 << ptoCount);
  }

  /// Should be invoked when an external timer set to [nextPtoTimeout]
  /// expires. Increments the PTO counter and asks the upper layer to
  /// send a probe.
  void onLossDetectionTimerExpired() {
    ptoCount++;
    onPtoProbe?.call();
  }

  /// Returns true iff there is at least one in-flight ack-eliciting
  /// packet still outstanding.
  bool get hasOutstandingAckEliciting =>
      _sent.values.any((p) => p.ackEliciting);

  /// Total bytes still considered in flight (matches CC accounting).
  int get bytesInFlight => cc.bytesInFlight;

  /// All packets currently in the sent-packet map (for diagnostics
  /// and tests). Order is unspecified.
  Iterable<SentPacket> get inFlightPackets => _sent.values;

  /// Drop tracking state for [pn]. Used when the upper layer decides
  /// not to count a packet (e.g. stateless reset).
  void discard(int pn) {
    final p = _sent.remove(pn);
    if (p != null) {
      cc.onPacketAcked(p.sizeInBytes, inFlight: p.inFlight, pn: p.pn);
    }
  }
}

/// Drives a [LossRecovery] from a Dart [Timer]. Splitting the timer
/// out keeps the algorithm core synchronous and unit-testable.
class PtoTimer {
  final LossRecovery recovery;
  Timer? _timer;
  Duration? _scheduledFor;

  PtoTimer(this.recovery);

  void rearm() {
    cancel();
    if (!recovery.hasOutstandingAckEliciting) return;
    _scheduledFor = recovery.nextPtoTimeout();
    _timer = Timer(_scheduledFor!, () {
      _timer = null;
      recovery.onLossDetectionTimerExpired();
      // Re-arm for the next probe.
      rearm();
    });
  }

  Duration? get scheduledFor => _scheduledFor;

  void cancel() {
    _timer?.cancel();
    _timer = null;
    _scheduledFor = null;
  }
}
