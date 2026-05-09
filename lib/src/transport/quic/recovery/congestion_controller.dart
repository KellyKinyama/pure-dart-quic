// NewReno congestion controller — RFC 9002 §7.
//
// Tracks bytes_in_flight, congestion window, slow-start threshold and
// recovery-period bookkeeping. Pacing and HyStart are not modelled.

class NewRenoController {
  /// `kInitialWindow` from RFC 9002 §7.2 — 10 × max_datagram_size.
  static const int kInitialWindowMul = 10;

  /// Minimum congestion window (`kMinimumWindow`).
  static const int kMinWindowMul = 2;

  /// Reduction factor on congestion event.
  static const double kLossReductionFactor = 0.5;

  final int maxDatagramSize;

  /// Current congestion window in bytes.
  int cwnd;

  /// Slow-start threshold, infinite until first loss.
  int ssthresh = 1 << 62;

  /// Bytes outstanding that count for congestion control.
  int bytesInFlight = 0;

  /// Largest packet number whose loss triggered the current recovery
  /// period; null when not in recovery.
  int? _recoveryStartPn;

  NewRenoController({this.maxDatagramSize = 1200})
    : cwnd = kInitialWindowMul * 1200;

  /// True when sending more in-flight bytes is allowed.
  bool canSend(int packetSize) => bytesInFlight + packetSize <= cwnd;

  /// Available space in the congestion window, in bytes.
  int get available {
    final a = cwnd - bytesInFlight;
    return a < 0 ? 0 : a;
  }

  void onPacketSent(int sizeInBytes, {required bool inFlight}) {
    if (!inFlight) return;
    bytesInFlight += sizeInBytes;
  }

  void onPacketAcked(int sizeInBytes, {required bool inFlight, int? pn}) {
    if (!inFlight) return;
    bytesInFlight -= sizeInBytes;
    if (bytesInFlight < 0) bytesInFlight = 0;

    // No CC growth while still recovering from a prior loss.
    if (_recoveryStartPn != null && pn != null && pn <= _recoveryStartPn!) {
      return;
    }
    if (_recoveryStartPn != null && pn != null && pn > _recoveryStartPn!) {
      _recoveryStartPn = null; // exit recovery
    }

    if (cwnd < ssthresh) {
      // Slow start.
      cwnd += sizeInBytes;
    } else {
      // Congestion avoidance: cwnd += MSS * acked / cwnd.
      cwnd += (maxDatagramSize * sizeInBytes) ~/ cwnd;
    }
  }

  /// Mark a packet as lost — adjust bytes_in_flight and possibly
  /// trigger a congestion event.
  void onPacketLost(int sizeInBytes, int pn, {required bool inFlight}) {
    if (!inFlight) return;
    bytesInFlight -= sizeInBytes;
    if (bytesInFlight < 0) bytesInFlight = 0;
    _enterRecovery(pn);
  }

  void _enterRecovery(int pn) {
    if (_recoveryStartPn != null && pn <= _recoveryStartPn!) return;
    _recoveryStartPn = pn;
    ssthresh = (cwnd * kLossReductionFactor).floor();
    final minCwnd = kMinWindowMul * maxDatagramSize;
    cwnd = ssthresh < minCwnd ? minCwnd : ssthresh;
  }

  bool get inRecovery => _recoveryStartPn != null;
}
