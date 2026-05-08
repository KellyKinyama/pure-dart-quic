// Pure unit tests for the AlpnRegistry.

import 'package:pure_dart_quic/pure_dart_quic.dart';
import 'package:test/test.dart';

void main() {
  group('AlpnRegistry', () {
    test('starts empty', () {
      final r = AlpnRegistry();
      expect(r.isEmpty, isTrue);
      expect(r.advertisedAlpns, isEmpty);
      expect(r.lookup('h3'), isNull);
    });

    test('register exposes all declared ALPN ids', () {
      final r = AlpnRegistry()..register(Http3ProtocolFactory());
      // Http3ProtocolFactory advertises at minimum 'h3'.
      expect(r.advertisedAlpns, contains('h3'));
      expect(r.lookup('h3'), isNotNull);
      expect(r.isEmpty, isFalse);
    });

    test('multiple factories coexist', () {
      final r = AlpnRegistry()
        ..register(Http3ProtocolFactory())
        ..register(XmppOverQuicProtocolFactory())
        ..register(MediaOverQuicProtocolFactory());

      expect(r.lookup('h3'), isNotNull);
      expect(r.lookup('xmpp-quic'), isNotNull);
      expect(r.lookup('moq-00'), isNotNull);
      expect(r.lookup('does-not-exist'), isNull);
    });

    test('advertisedAlpns preserves registration order', () {
      final r = AlpnRegistry()
        ..register(XmppOverQuicProtocolFactory())
        ..register(Http3ProtocolFactory());
      final list = r.advertisedAlpns;
      expect(list.first, 'xmpp-quic');
      expect(list, contains('h3'));
    });
  });
}
