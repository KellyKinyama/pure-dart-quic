// RFC 9002 §5 RTT estimator.
//
// Smoothed round-trip-time + RTT variation, plus min_rtt and the
// most recently observed sample. All times are in microseconds.

import 'dart:math' as math;

class RttEstimator {
  /// `kGranularity` from RFC 9002 §6.1.2 (1 ms).
  static const int kGranularityUs = 1000;

  /// Initial RTT before any sample, RFC 9002 §6.2.2 (333 ms).
  static const int kInitialRttUs = 333000;

  /// Smoothed RTT (μs). Uninitialised until first sample.
  int? _smoothedRtt;

  /// RTT variance (μs).
  int? _rttVar;

  /// Minimum RTT observed across the connection (μs).
  int? _minRtt;

  /// Most recent RTT sample (μs).
  int? _latestRtt;

  /// Maximum ack delay advertised by peer (μs). Defaults to 25 ms.
  int maxAckDelayUs = 25000;

  int? get smoothedRtt => _smoothedRtt;
  int? get rttVar => _rttVar;
  int? get minRtt => _minRtt;
  int? get latestRtt => _latestRtt;

  /// Effective SRTT for PTO / loss-time computations: returns the
  /// initial RTT until a real sample is observed.
  int get smoothedRttOrInitial => _smoothedRtt ?? kInitialRttUs;

  /// Effective RTTVAR for PTO computations.
  int get rttVarOrInitial => _rttVar ?? (kInitialRttUs ~/ 2);

  /// Apply a new RTT sample. [ackDelayUs] is the ACK_DELAY field from
  /// the peer's ACK frame (already converted to microseconds).
  /// [isHandshakeConfirmed] is true once the handshake has completed.
  void onRttSample({
    required int rttSampleUs,
    required int ackDelayUs,
    required bool isHandshakeConfirmed,
  }) {
    if (rttSampleUs <= 0) return;

    _latestRtt = rttSampleUs;
    if (_minRtt == null || rttSampleUs < _minRtt!) {
      _minRtt = rttSampleUs;
    }

    if (_smoothedRtt == null) {
      // First sample.
      _smoothedRtt = rttSampleUs;
      _rttVar = rttSampleUs ~/ 2;
      return;
    }

    // Adjust ack_delay (RFC 9002 §5.3): cap at max_ack_delay once the
    // handshake is confirmed; ignore before that.
    var adjustedRtt = rttSampleUs;
    final cap = isHandshakeConfirmed ? maxAckDelayUs : 0;
    if (_minRtt != null && rttSampleUs >= _minRtt! + ackDelayUs) {
      final useDelay = math.min(ackDelayUs, cap);
      adjustedRtt = rttSampleUs - useDelay;
    }

    final srtt = _smoothedRtt!;
    final varRtt = _rttVar!;
    _rttVar = ((3 * varRtt) + (srtt - adjustedRtt).abs()) ~/ 4;
    _smoothedRtt = ((7 * srtt) + adjustedRtt) ~/ 8;
  }

  /// Probe Timeout per RFC 9002 §6.2.1.
  Duration ptoBase() {
    final srtt = smoothedRttOrInitial;
    final varRtt = rttVarOrInitial;
    final us = srtt + math.max<int>(4 * varRtt, kGranularityUs) + maxAckDelayUs;
    return Duration(microseconds: us);
  }
}
