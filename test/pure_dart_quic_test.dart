// Smoke test for the modular package surface — ensures the public
// exports compile and basic constructors succeed without I/O.

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

void main() {
  test('AlpnRegistry default state', () {
    final r = AlpnRegistry();
    expect(r.isEmpty, isTrue);
  });

  test('every shipped protocol factory exposes its ALPN ids', () {
    expect(Http3ProtocolFactory().alpnIds, contains('h3'));
    expect(WebTransportProtocolFactory().alpnIds, isNotEmpty);
    expect(XmppOverQuicProtocolFactory().alpnIds, contains('xmpp-quic'));
    expect(MediaOverQuicProtocolFactory().alpnIds, contains('moq-00'));
    expect(SipOverQuicProtocolFactory().alpnIds, contains('sip'));
  });

  test('legacy calculate() stub still returns 42', () {
    expect(calculate(), 42);
  });
}
