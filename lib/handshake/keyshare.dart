import 'dart:typed_data';

import '../byte_reader.dart';
import 'client_hello.dart';
import 'tls_messages.dart';

class ParsedKeyShare {
  final int group;
  final Uint8List pub;

  ParsedKeyShare(this.group, this.pub);

  @override
  String toString() {
    // TODO: implement toString
    return "Keyshare{ groutp:${supportedGroupsMap[group] != null ? (supportedGroupsMap[group]) : group}}";
  }
}

/// QUIC ClientHello KeyShare parser (RFC 9001)
/// QUIC ALWAYS wraps key_share in a vector:
///   uint16 key_share_list_length;
///   KeyShareEntry entries[key_share_list_length];
ParsedKeyShare extractClientKeyShare(ClientHello ch) {
  final ext = ch.extensions.firstWhere(
    (e) => e.type == 51,
    orElse: () => throw "Client did not send key_share",
  );

  final r = ByteReader(ext.data);

  // ✅ QUIC ALWAYS has a 16-bit list length first, so ALWAYS skip it.
  // This is the bug that caused group = 0x24.
  // final listLength = r.readUint16be();

  // (Optional) Debug
  // print("✅ key_share_list_length = $listLength");

  // ✅ Now read actual KeyShareEntry
  final group = r.readUint16be();
  final kxLen = r.readUint16be();
  final pub = r.readBytes(kxLen);

  return ParsedKeyShare(group, pub);
}
