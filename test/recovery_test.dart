// Unit tests for the RFC 9002 loss-recovery + NewReno modules.

import 'dart:typed_data';

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

SentPacket _pkt(
  int pn,
  DateTime t, {
  int size = 1200,
  bool ackEliciting = true,
}) => SentPacket(
  pn: pn,
  sentTime: t,
  sizeInBytes: size,
  ackEliciting: ackEliciting,
  inFlight: ackEliciting,
  frames: [
    StreamFrameRecord(streamId: 0, offset: 0, data: Uint8List(0), fin: false),
  ],
);

void main() {
  group('RttEstimator', () {
    test('first sample seeds srtt and rttvar', () {
      final r = RttEstimator();
      expect(r.smoothedRtt, isNull);
      r.onRttSample(
        rttSampleUs: 200000,
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
      );
      expect(r.smoothedRtt, 200000);
      expect(r.rttVar, 100000);
      expect(r.minRtt, 200000);
      expect(r.latestRtt, 200000);
    });

    test('subsequent samples smooth toward new value', () {
      final r = RttEstimator();
      r.onRttSample(
        rttSampleUs: 200000,
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
      );
      r.onRttSample(
        rttSampleUs: 300000,
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
      );
      expect(r.smoothedRtt, greaterThan(200000));
      expect(r.smoothedRtt, lessThan(300000));
      expect(r.minRtt, 200000);
    });

    test('ack_delay reduces sample once handshake confirmed', () {
      final r = RttEstimator();
      r.onRttSample(
        rttSampleUs: 200000,
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
      );
      // 250 ms RTT with 25 ms ack delay → adjusted = 225 ms.
      r.onRttSample(
        rttSampleUs: 250000,
        ackDelayUs: 25000,
        isHandshakeConfirmed: true,
      );
      expect(r.smoothedRtt, lessThan(250000));
    });

    test('rejects non-positive samples', () {
      final r = RttEstimator();
      r.onRttSample(rttSampleUs: 0, ackDelayUs: 0, isHandshakeConfirmed: true);
      expect(r.smoothedRtt, isNull);
    });

    test('PTO base = srtt + 4*rttvar + max_ack_delay (>= granularity)', () {
      final r = RttEstimator();
      r.onRttSample(
        rttSampleUs: 100000,
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
      );
      // srtt=100ms rttvar=50ms ack_delay=25ms ⇒ 100 + 200 + 25 = 325 ms.
      final pto = r.ptoBase();
      expect(pto.inMilliseconds, inInclusiveRange(320, 330));
    });
  });

  group('NewRenoController', () {
    test('initial cwnd is 10 * MSS', () {
      final c = NewRenoController(maxDatagramSize: 1200);
      expect(c.cwnd, 12000);
      expect(c.bytesInFlight, 0);
      expect(c.canSend(1200), isTrue);
    });

    test('slow-start increases cwnd by acked bytes', () {
      final c = NewRenoController(maxDatagramSize: 1200);
      c.onPacketSent(1200, inFlight: true);
      c.onPacketAcked(1200, inFlight: true, pn: 0);
      expect(c.cwnd, 13200);
    });

    test('loss halves cwnd and sets ssthresh', () {
      final c = NewRenoController(maxDatagramSize: 1200);
      c.onPacketSent(1200, inFlight: true);
      c.onPacketLost(1200, 0, inFlight: true);
      expect(c.cwnd, lessThanOrEqualTo(6000));
      expect(c.ssthresh, c.cwnd);
      expect(c.inRecovery, isTrue);
    });

    test('cwnd never falls below 2 * MSS after loss', () {
      final c = NewRenoController(maxDatagramSize: 1200);
      // Force a tiny cwnd by repeated loss.
      for (var i = 0; i < 20; i++) {
        c.onPacketSent(1200, inFlight: true);
        c.onPacketLost(1200, i, inFlight: true);
      }
      expect(c.cwnd, greaterThanOrEqualTo(2400));
    });

    test('canSend gates by cwnd', () {
      final c = NewRenoController(maxDatagramSize: 1200);
      c.onPacketSent(12000, inFlight: true);
      expect(c.canSend(1), isFalse);
    });

    test('packets ack-ed during recovery do not grow cwnd', () {
      final c = NewRenoController(maxDatagramSize: 1200);
      c.onPacketSent(1200, inFlight: true);
      c.onPacketLost(1200, 5, inFlight: true);
      final cwndAfterLoss = c.cwnd;
      c.onPacketSent(1200, inFlight: true);
      c.onPacketAcked(1200, inFlight: true, pn: 4); // <= recoveryStart
      expect(c.cwnd, cwndAfterLoss);
    });
  });

  group('LossRecovery', () {
    test('ack removes packet and grows cwnd in slow start', () {
      final r = LossRecovery(rtt: RttEstimator(), cc: NewRenoController());
      final t0 = DateTime.now();
      r.onPacketSent(_pkt(0, t0));
      expect(r.cc.bytesInFlight, 1200);

      r.onAckReceived(
        largestAcked: 0,
        ackedRanges: [(0, 0)],
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
        now: t0.add(const Duration(milliseconds: 50)),
      );
      expect(r.cc.bytesInFlight, 0);
      expect(r.rtt.smoothedRtt, 50000);
    });

    test('packet-threshold triggers loss for older PNs', () {
      final r = LossRecovery(rtt: RttEstimator(), cc: NewRenoController());
      final t0 = DateTime.now();
      for (var i = 0; i < 5; i++) {
        r.onPacketSent(_pkt(i, t0.add(Duration(microseconds: i * 1000))));
      }

      final lostList = <SentPacket>[];
      r.onPacketsLost = lostList.addAll;

      // Acknowledge only PN=4. PNs 0..1 are >=3 behind ⇒ lost.
      r.onAckReceived(
        largestAcked: 4,
        ackedRanges: [(4, 4)],
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
        now: t0.add(const Duration(milliseconds: 50)),
      );

      final lostPns = lostList.map((p) => p.pn).toList()..sort();
      expect(lostPns, containsAll([0, 1]));
      // PN=2,3 are within the 3-packet window — only time-threshold could
      // declare them lost, which won't fire at t0+50ms.
      expect(lostPns, isNot(contains(2)));
      expect(lostPns, isNot(contains(3)));
    });

    test('time-threshold declares old packets lost', () async {
      final r = LossRecovery(rtt: RttEstimator(), cc: NewRenoController());
      final t0 = DateTime.now();
      // First sample establishes a small SRTT.
      r.onPacketSent(_pkt(0, t0));
      r.onAckReceived(
        largestAcked: 0,
        ackedRanges: [(0, 0)],
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
        now: t0.add(const Duration(milliseconds: 10)),
      );
      // SRTT now ~10 ms; time threshold ~11.25 ms.
      r.onPacketSent(_pkt(10, t0.add(const Duration(seconds: 1))));
      r.onPacketSent(_pkt(11, t0.add(const Duration(seconds: 2))));
      final lost = <SentPacket>[];
      r.onPacketsLost = lost.addAll;

      // Ack PN=11 a long time later → PN=10 is older than threshold.
      r.onAckReceived(
        largestAcked: 11,
        ackedRanges: [(11, 11)],
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
        now: t0.add(const Duration(seconds: 3)),
      );
      expect(lost.map((p) => p.pn), contains(10));
    });

    test('PTO base doubles on consecutive expirations', () {
      final r = LossRecovery(rtt: RttEstimator(), cc: NewRenoController());
      final base = r.nextPtoTimeout();
      r.onLossDetectionTimerExpired();
      expect(r.nextPtoTimeout(), base * 2);
      r.onLossDetectionTimerExpired();
      expect(r.nextPtoTimeout(), base * 4);
    });

    test('hasOutstandingAckEliciting reflects in-flight packets', () {
      final r = LossRecovery(rtt: RttEstimator(), cc: NewRenoController());
      expect(r.hasOutstandingAckEliciting, isFalse);
      r.onPacketSent(_pkt(0, DateTime.now()));
      expect(r.hasOutstandingAckEliciting, isTrue);
      r.onAckReceived(
        largestAcked: 0,
        ackedRanges: [(0, 0)],
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
        now: DateTime.now(),
      );
      expect(r.hasOutstandingAckEliciting, isFalse);
    });
  });

  // -------------------------------------------------------------------------
  // Integration-style scenarios that mirror what the QuicConnection
  // adapters do: send → loss → retransmit + CC halving → cwnd-gated queueing.
  // -------------------------------------------------------------------------
  group('LossRecovery + NewReno integration', () {
    test('lost STREAM frame is retransmitted and cwnd is halved', () {
      final cc = NewRenoController();
      final r = LossRecovery(rtt: RttEstimator(), cc: cc);

      final retransmitted = <StreamFrameRecord>[];
      r.onPacketsLost = (lost) {
        for (final p in lost) {
          for (final f in p.frames) {
            if (f is StreamFrameRecord) retransmitted.add(f);
          }
        }
      };

      // Identify the lost stream frame by data byte so we can recognise it.
      SentPacket mk(int pn, DateTime t, int marker) => SentPacket(
        pn: pn,
        sentTime: t,
        sizeInBytes: 1200,
        ackEliciting: true,
        inFlight: true,
        frames: [
          StreamFrameRecord(
            streamId: 0,
            offset: marker,
            data: Uint8List.fromList([marker]),
            fin: false,
          ),
        ],
      );

      final cwnd0 = cc.cwnd;
      final t0 = DateTime.now();
      for (var i = 0; i < 5; i++) {
        r.onPacketSent(mk(i, t0.add(Duration(microseconds: i * 1000)), i));
      }
      expect(cc.bytesInFlight, 5 * 1200);

      // Ack PN=4 only ⇒ PN=0 and PN=1 are >=3 behind ⇒ packet-threshold loss.
      r.onAckReceived(
        largestAcked: 4,
        ackedRanges: [(4, 4)],
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
        now: t0.add(const Duration(milliseconds: 50)),
      );

      expect(retransmitted.map((f) => f.offset), containsAll([0, 1]));
      // NewReno halves on each distinct loss; with two losses cwnd is
      // reduced twice from the initial window.
      expect(cc.cwnd, lessThan(cwnd0));
      expect(cc.cwnd, lessThanOrEqualTo(cwnd0 ~/ 2));
      expect(cc.inRecovery, isTrue);
    });

    test('cwnd gating queues writes; drain after ACK frees in-flight', () {
      // Mirror the adapter's queueing logic locally.
      final cc = NewRenoController();
      final r = LossRecovery(rtt: RttEstimator(), cc: cc);

      var nextPn = 0;
      final inFlightFrames = <int, StreamFrameRecord>{};
      final queue = <StreamFrameRecord>[];

      void rawSend(StreamFrameRecord f) {
        final pn = nextPn++;
        inFlightFrames[pn] = f;
        r.onPacketSent(
          SentPacket(
            pn: pn,
            sentTime: DateTime.now(),
            sizeInBytes: 1200,
            ackEliciting: true,
            inFlight: true,
            frames: [f],
          ),
        );
      }

      void send(StreamFrameRecord f) {
        if (!cc.canSend(f.data.length + 50)) {
          queue.add(f);
          return;
        }
        rawSend(f);
      }

      void drain() {
        while (queue.isNotEmpty && cc.canSend(queue.first.data.length + 50)) {
          rawSend(queue.removeAt(0));
        }
      }

      // Initial cwnd = 12000 B. Each in-flight packet is 1200 B and the
      // adapter-style send check uses (data.length + 50) for headroom,
      // so 9 packets fit (10800 B) before a 10th would exceed cwnd.
      for (var i = 0; i < 11; i++) {
        send(
          StreamFrameRecord(
            streamId: 0,
            offset: i,
            data: Uint8List(1200),
            fin: false,
          ),
        );
      }
      expect(inFlightFrames.length, 9);
      expect(queue.length, 2);
      expect(cc.bytesInFlight, 9 * 1200);

      // Ack the first 5 packets ⇒ frees 6000 B ⇒ queued frames flush.
      r.onAckReceived(
        largestAcked: 4,
        ackedRanges: [(0, 4)],
        ackDelayUs: 0,
        isHandshakeConfirmed: true,
      );
      drain();
      expect(queue, isEmpty);
      // Both previously-queued frames should now be in flight.
      expect(inFlightFrames.keys, containsAll([9, 10]));
    });
  });
}
