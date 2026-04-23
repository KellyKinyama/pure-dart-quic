import 'dart:typed_data';
// import 'dart:typed_data';
import '../buffer.dart';
import 'tls_msg.dart';

Uint8List buildCertificateMessage(List<Uint8List> certChain) {
  final builder = BytesBuilder();

  // Context length = 0 for QUIC/TLS 1.3
  builder.addByte(0x00);

  // Build certificate list
  final certListBuilder = BytesBuilder();

  for (final cert in certChain) {
    // Cert length (3 bytes)
    certListBuilder.add([
      (cert.length >> 16) & 0xff,
      (cert.length >> 8) & 0xff,
      cert.length & 0xff,
    ]);

    // Certificate data
    certListBuilder.add(cert);

    // Extensions length = 0 (no per‑certificate extensions)
    certListBuilder.add([0x00, 0x00]);
  }

  final certList = certListBuilder.toBytes();

  // Certificate_list length (3 bytes)
  builder.add([
    (certList.length >> 16) & 0xff,
    (certList.length >> 8) & 0xff,
    certList.length & 0xff,
  ]);

  builder.add(certList);

  final body = builder.toBytes();

  // Handshake header (type=0x0B)
  final header = Uint8List.fromList([
    0x0B,
    (body.length >> 16) & 0xff,
    (body.length >> 8) & 0xff,
    body.length & 0xff,
  ]);

  return Uint8List.fromList([...header, ...body]);
}

// certificate.dart

class CertificateEntry {
  final Uint8List cert;
  final Uint8List extensions;

  CertificateEntry(this.cert, this.extensions);
}

class CertificateMessage extends TlsHandshakeMessage {
  final Uint8List context; // usually 0x00
  final List<CertificateEntry> certificates;

  CertificateMessage({required this.context, required this.certificates})
    : super(0x0B);

  // ---------------------------------------------------------
  // ✅ PARSER
  // ---------------------------------------------------------
  static CertificateMessage parse(QuicBuffer buf) {
    // certificate_request_context
    final ctxLen = buf.pullUint8();
    final context = buf.pullBytes(ctxLen);

    // certificate_list length (uint24)
    final listLen = buf.pullUint24();
    final end = buf.readOffset + listLen;

    final certs = <CertificateEntry>[];

    while (buf.readOffset < end) {
      final certLen = buf.pullUint24();
      final cert = buf.pullBytes(certLen);

      final extLen = buf.pullUint16();
      final ext = buf.pullBytes(extLen);

      certs.add(CertificateEntry(cert, ext));
    }

    return CertificateMessage(context: context, certificates: certs);
  }

  // ---------------------------------------------------------
  // ✅ BUILDER  (like JS build_certificate)
  // ---------------------------------------------------------
  Uint8List build() {
    final bb = BytesBuilder();

    // certificate_request_context
    bb.add([context.length]);
    bb.add(context);

    // build certificate_list
    final list = BytesBuilder();
    for (final entry in certificates) {
      list.add([
        (entry.cert.length >> 16) & 0xFF,
        (entry.cert.length >> 8) & 0xFF,
        entry.cert.length & 0xFF,
      ]);
      list.add(entry.cert);
      list.add([
        (entry.extensions.length >> 8) & 0xFF,
        entry.extensions.length & 0xFF,
      ]);
      list.add(entry.extensions);
    }

    final listBytes = list.toBytes();

    // prepend length
    bb.add([
      (listBytes.length >> 16) & 0xFF,
      (listBytes.length >> 8) & 0xFF,
      listBytes.length & 0xFF,
    ]);
    bb.add(listBytes);

    final body = bb.toBytes();

    final header = [
      msgType,
      (body.length >> 16) & 0xFF,
      (body.length >> 8) & 0xFF,
      body.length & 0xFF,
    ];

    return Uint8List.fromList([...header, ...body]);
  }

  @override
  String toString() => "✅ CertificateMessage(${certificates.length} certs)";
}
