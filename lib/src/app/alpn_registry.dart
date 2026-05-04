// ALPN -> ApplicationProtocolFactory registry.
//
// QUIC endpoints consult this registry after the TLS handshake to
// instantiate the correct application protocol on top of a connection.

import 'application_protocol.dart';

class AlpnRegistry {
  final Map<String, ApplicationProtocolFactory> _byAlpn = {};

  /// Register a factory under each of its declared ALPN ids.
  void register(ApplicationProtocolFactory factory) {
    for (final id in factory.alpnIds) {
      _byAlpn[id] = factory;
    }
  }

  /// Lookup by ALPN. Returns null if no protocol is registered.
  ApplicationProtocolFactory? lookup(String alpn) => _byAlpn[alpn];

  /// All ALPN ids registered, in registration order. Suitable to
  /// advertise in a ClientHello or accept in a ServerHello.
  List<String> get advertisedAlpns => _byAlpn.keys.toList(growable: false);

  bool get isEmpty => _byAlpn.isEmpty;
}
