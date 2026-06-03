// PSK offer for TLS 1.3 session resumption (RFC 8446 §4.2.11).
//
// pre_shared_key is the LAST extension in a ClientHello that offers
// resumption. Its wire layout is, for a single identity:
//
//   identities_list_len  uint16   = 2 + identity.len + 4
//     identity_len       uint16
//     identity           opaque[identity.len]
//     obfuscated_age     uint32
//   binders_list_len     uint16   = 1 + binder.len
//     binder_len         uint8    = binder.len
//     binder             opaque[binder.len]
//
// The binder value is HMAC(finished_key, transcript_hash(truncated_CH))
// where truncated_CH is the on-the-wire ClientHello up to but NOT
// including the binders_list_len field. Computing the binder therefore
// requires a two-pass build: emit the CH with binder bytes zeroed,
// hand the truncated prefix back to the caller, let the caller compute
// the real binder, then patch it in at the returned [binderOffset].

import 'dart:typed_data';

/// A single resumption PSK to offer in ClientHello.
class PskOffer {
  /// Opaque ticket from a prior NewSessionTicket. Sent as the
  /// `identity` field of the first (and only) PskIdentity entry.
  final Uint8List identity;

  /// `(real_age_ms + ticket_age_add) mod 2^32`, where real_age_ms is
  /// the number of milliseconds since the client received the ticket
  /// from the server. See RFC 8446 §4.2.11.1.
  final int obfuscatedTicketAge;

  /// Length of the binder HMAC output for the suite this PSK was
  /// issued under — 32 for SHA-256 suites, 48 for SHA-384.
  final int binderLen;

  /// If true, also emit an empty `early_data` extension (0x002a) in
  /// ClientHello so the server may accept 0-RTT data.
  final bool offerEarlyData;

  const PskOffer({
    required this.identity,
    required this.obfuscatedTicketAge,
    required this.binderLen,
    this.offerEarlyData = false,
  });
}

/// Output of [buildClientHelloWithPsk].
class BuiltClientHello {
  /// Full on-the-wire ClientHello bytes (handshake header + body),
  /// with the binder bytes zeroed pending caller patching.
  final Uint8List bytes;

  /// Offset (within [bytes]) of the first binder byte. Null if no PSK
  /// was offered. The caller must overwrite
  /// `bytes[binderOffset .. binderOffset+binderLen]` with the HMAC
  /// computed over `bytes[0 .. binderOffset-3]` (the `-3` strips the
  /// 2-byte binders_list_len + 1-byte binder_len prefix that are NOT
  /// part of the binder input — see RFC 8446 §4.2.11.2).
  final int? binderOffset;

  /// Length of the binder slot (same as [PskOffer.binderLen]).
  final int? binderLen;

  /// Convenience: the prefix of [bytes] that the binder is computed
  /// over (everything up to but not including the binders_list_len
  /// field). Null if no PSK was offered.
  Uint8List? get truncatedForBinder {
    final off = binderOffset;
    if (off == null) return null;
    // binders_list_len(2) + binder_len(1) + binder(N) = 3 + binderLen!
    return Uint8List.sublistView(bytes, 0, off - 3);
  }

  const BuiltClientHello({
    required this.bytes,
    this.binderOffset,
    this.binderLen,
  });
}
