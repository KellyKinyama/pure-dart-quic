/*
 * quico: HTTP/3 and QUIC implementation for Node.js
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * This file is part of the open-source project hosted at:
 *     https://github.com/colocohen/quico
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

import 'dart:convert';
import 'dart:typed_data';

import '../../utils.dart';

/// ============================================================
/// QPACK / HPACK Huffman tables
/// ============================================================

final Uint32List huffman_codes = Uint32List.fromList([
  0x1ff8, // (0)
  0x7fffd8, // (1)
  0xfffffe2, // (2)
  0xfffffe3, // (3)
  0xfffffe4, // (4)
  0xfffffe5, // (5)
  0xfffffe6, // (6)
  0xfffffe7, // (7)
  0xfffffe8, // (8)
  0xffffea, // (9)
  0x3ffffffc, // (10)
  0xfffffe9, // (11)
  0xfffffea, // (12)
  0x3ffffffd, // (13)
  0xfffffeb, // (14)
  0xfffffec, // (15)
  0xfffffed, // (16)
  0xfffffee, // (17)
  0xfffffef, // (18)
  0xffffff0, // (19)
  0xffffff1, // (20)
  0xffffff2, // (21)
  0x3ffffffe, // (22)
  0xffffff3, // (23)
  0xffffff4, // (24)
  0xffffff5, // (25)
  0xffffff6, // (26)
  0xffffff7, // (27)
  0xffffff8, // (28)
  0xffffff9, // (29)
  0xffffffa, // (30)
  0xffffffb, // (31)
  0x14, // ' ' (32)
  0x3f8, // '!' (33)
  0x3f9, // '"' (34)
  0xffa, // '#' (35)
  0x1ff9, // '$' (36)
  0x15, // '%' (37)
  0xf8, // '&' (38)
  0x7fa, // '\'' (39)
  0x3fa, // '(' (40)
  0x3fb, // ')' (41)
  0xf9, // '*' (42)
  0x7fb, // '+' (43)
  0xfa, // ',' (44)
  0x16, // '-' (45)
  0x17, // '.' (46)
  0x18, // '/' (47)
  0x0, // '0' (48)
  0x1, // '1' (49)
  0x2, // '2' (50)
  0x19, // '3' (51)
  0x1a, // '4' (52)
  0x1b, // '5' (53)
  0x1c, // '6' (54)
  0x1d, // '7' (55)
  0x1e, // '8' (56)
  0x1f, // '9' (57)
  0x5c, // ':' (58)
  0xfb, // ';' (59)
  0x7ffc, // '<' (60)
  0x20, // '=' (61)
  0xffb, // '>' (62)
  0x3fc, // '?' (63)
  0x1ffa, // '@' (64)
  0x21, // 'A' (65)
  0x5d, // 'B' (66)
  0x5e, // 'C' (67)
  0x5f, // 'D' (68)
  0x60, // 'E' (69)
  0x61, // 'F' (70)
  0x62, // 'G' (71)
  0x63, // 'H' (72)
  0x64, // 'I' (73)
  0x65, // 'J' (74)
  0x66, // 'K' (75)
  0x67, // 'L' (76)
  0x68, // 'M' (77)
  0x69, // 'N' (78)
  0x6a, // 'O' (79)
  0x6b, // 'P' (80)
  0x6c, // 'Q' (81)
  0x6d, // 'R' (82)
  0x6e, // 'S' (83)
  0x6f, // 'T' (84)
  0x70, // 'U' (85)
  0x71, // 'V' (86)
  0x72, // 'W' (87)
  0xfc, // 'X' (88)
  0x73, // 'Y' (89)
  0xfd, // 'Z' (90)
  0x1ffb, // '[' (91)
  0x7fff0, // '\' (92)
  0x1ffc, // ']' (93)
  0x3ffc, // '^' (94)
  0x22, // '_' (95)
  0x7ffd, // '`' (96)
  0x3, // 'a' (97)
  0x23, // 'b' (98)
  0x4, // 'c' (99)
  0x24, // 'd' (100)
  0x5, // 'e' (101)
  0x25, // 'f' (102)
  0x26, // 'g' (103)
  0x27, // 'h' (104)
  0x6, // 'i' (105)
  0x74, // 'j' (106)
  0x75, // 'k' (107)
  0x28, // 'l' (108)
  0x29, // 'm' (109)
  0x2a, // 'n' (110)
  0x7, // 'o' (111)
  0x2b, // 'p' (112)
  0x76, // 'q' (113)
  0x2c, // 'r' (114)
  0x8, // 's' (115)
  0x9, // 't' (116)
  0x2d, // 'u' (117)
  0x77, // 'v' (118)
  0x78, // 'w' (119)
  0x79, // 'x' (120)
  0x7a, // 'y' (121)
  0x7b, // 'z' (122)
  0x7ffe, // '{' (123)
  0x7fc, // '|' (124)
  0x3ffd, // '}' (125)
  0x1ffd, // '~' (126)
  0xffffffc, // (127)
  0xfffe6, // (128)
  0x3fffd2, // (129)
  0xfffe7, // (130)
  0xfffe8, // (131)
  0x3fffd3, // (132)
  0x3fffd4, // (133)
  0x3fffd5, // (134)
  0x7fffd9, // (135)
  0x3fffd6, // (136)
  0x7fffda, // (137)
  0x7fffdb, // (138)
  0x7fffdc, // (139)
  0x7fffdd, // (140)
  0x7fffde, // (141)
  0xffffeb, // (142)
  0x7fffdf, // (143)
  0xffffec, // (144)
  0xffffed, // (145)
  0x3fffd7, // (146)
  0x7fffe0, // (147)
  0xffffee, // (148)
  0x7fffe1, // (149)
  0x7fffe2, // (150)
  0x7fffe3, // (151)
  0x7fffe4, // (152)
  0x1fffdc, // (153)
  0x3fffd8, // (154)
  0x7fffe5, // (155)
  0x3fffd9, // (156)
  0x7fffe6, // (157)
  0x7fffe7, // (158)
  0xffffef, // (159)
  0x3fffda, // (160)
  0x1fffdd, // (161)
  0xfffe9, // (162)
  0x3fffdb, // (163)
  0x3fffdc, // (164)
  0x7fffe8, // (165)
  0x7fffe9, // (166)
  0x1fffde, // (167)
  0x7fffea, // (168)
  0x3fffdd, // (169)
  0x3fffde, // (170)
  0xfffff0, // (171)
  0x1fffdf, // (172)
  0x3fffdf, // (173)
  0x7fffeb, // (174)
  0x7fffec, // (175)
  0x1fffe0, // (176)
  0x1fffe1, // (177)
  0x3fffe0, // (178)
  0x1fffe2, // (179)
  0x7fffed, // (180)
  0x3fffe1, // (181)
  0x7fffee, // (182)
  0x7fffef, // (183)
  0xfffea, // (184)
  0x3fffe2, // (185)
  0x3fffe3, // (186)
  0x3fffe4, // (187)
  0x7ffff0, // (188)
  0x3fffe5, // (189)
  0x3fffe6, // (190)
  0x7ffff1, // (191)
  0x3ffffe0, // (192)
  0x3ffffe1, // (193)
  0xfffeb, // (194)
  0x7fff1, // (195)
  0x3fffe7, // (196)
  0x7ffff2, // (197)
  0x3fffe8, // (198)
  0x1ffffec, // (199)
  0x3ffffe2, // (200)
  0x3ffffe3, // (201)
  0x3ffffe4, // (202)
  0x7ffffde, // (203)
  0x7ffffdf, // (204)
  0x3ffffe5, // (205)
  0xfffff1, // (206)
  0x1ffffed, // (207)
  0x7fff2, // (208)
  0x1fffe3, // (209)
  0x3ffffe6, // (210)
  0x7ffffe0, // (211)
  0x7ffffe1, // (212)
  0x3ffffe7, // (213)
  0x7ffffe2, // (214)
  0xfffff2, // (215)
  0x1fffe4, // (216)
  0x1fffe5, // (217)
  0x3ffffe8, // (218)
  0x3ffffe9, // (219)
  0xffffffd, // (220)
  0x7ffffe3, // (221)
  0x7ffffe4, // (222)
  0x7ffffe5, // (223)
  0xfffec, // (224)
  0xfffff3, // (225)
  0xfffed, // (226)
  0x1fffe6, // (227)
  0x3fffe9, // (228)
  0x1fffe7, // (229)
  0x1fffe8, // (230)
  0x7ffff3, // (231)
  0x3fffea, // (232)
  0x3fffeb, // (233)
  0x1ffffee, // (234)
  0x1ffffef, // (235)
  0xfffff4, // (236)
  0xfffff5, // (237)
  0x3ffffea, // (238)
  0x7ffff4, // (239)
  0x3ffffeb, // (240)
  0x7ffffe6, // (241)
  0x3ffffec, // (242)
  0x3ffffed, // (243)
  0x7ffffe7, // (244)
  0x7ffffe8, // (245)
  0x7ffffe9, // (246)
  0x7ffffea, // (247)
  0x7ffffeb, // (248)
  0xffffffe, // (249)
  0x7ffffec, // (250)
  0x7ffffed, // (251)
  0x7ffffee, // (252)
  0x7ffffef, // (253)
  0x7fffff0, // (254)
  0x3ffffee, // (255)
  0x3fffffff, // EOS (256)
]);

final Uint8List huffman_bits = Uint8List.fromList([
  13,
  23,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  24,
  30,
  28,
  28,
  30,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  30,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  6,
  10,
  10,
  12,
  13,
  6,
  8,
  11,
  10,
  10,
  8,
  11,
  8,
  6,
  6,
  6,
  5,
  5,
  5,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  7,
  8,
  15,
  6,
  12,
  10,
  13,
  6,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  8,
  7,
  8,
  13,
  19,
  13,
  14,
  6,
  15,
  5,
  6,
  5,
  6,
  5,
  6,
  6,
  6,
  5,
  7,
  7,
  6,
  6,
  6,
  5,
  6,
  7,
  6,
  5,
  5,
  6,
  7,
  7,
  7,
  7,
  7,
  15,
  11,
  14,
  13,
  28,
  20,
  22,
  20,
  20,
  22,
  22,
  22,
  23,
  22,
  23,
  23,
  23,
  23,
  23,
  24,
  23,
  24,
  24,
  22,
  23,
  24,
  23,
  23,
  23,
  23,
  21,
  22,
  23,
  22,
  23,
  23,
  24,
  22,
  21,
  20,
  22,
  22,
  23,
  23,
  21,
  23,
  22,
  22,
  24,
  21,
  22,
  23,
  23,
  21,
  21,
  22,
  21,
  23,
  22,
  23,
  23,
  20,
  22,
  22,
  22,
  23,
  22,
  22,
  23,
  26,
  26,
  20,
  19,
  22,
  23,
  22,
  25,
  26,
  26,
  26,
  27,
  27,
  26,
  24,
  25,
  19,
  21,
  26,
  27,
  27,
  26,
  27,
  24,
  21,
  21,
  26,
  26,
  28,
  27,
  27,
  27,
  20,
  24,
  20,
  21,
  22,
  21,
  21,
  23,
  22,
  22,
  25,
  25,
  24,
  24,
  26,
  23,
  26,
  27,
  26,
  26,
  27,
  27,
  27,
  27,
  27,
  28,
  27,
  27,
  27,
  27,
  27,
  26,
  30,
]);

/// ============================================================
/// Utility models
/// ============================================================

class TrieNode {
  TrieNode? zero;
  TrieNode? one;
  int? symbol;
}

class DecodeVarIntResult {
  final int value;
  final int next;

  DecodeVarIntResult(this.value, this.next);
}

class QpackHeaderField {
  final String name;
  final String value;

  const QpackHeaderField(this.name, this.value);

  @override
  String toString() => '$name: $value';
}

class _PosRef {
  int pos;
  _PosRef(this.pos);
}

/// ============================================================
/// Huffman trie
/// ============================================================

TrieNode buildHuffmanDecodeTrie() {
  final root = TrieNode();

  for (var i = 0; i < huffman_codes.length; i++) {
    final code = huffman_codes[i];
    final length = huffman_bits[i];
    var node = root;

    for (var j = length - 1; j >= 0; j--) {
      final bit = (code >> j) & 1;
      if (bit == 0) {
        node.zero ??= TrieNode();
        node = node.zero!;
      } else {
        node.one ??= TrieNode();
        node = node.one!;
      }
    }

    node.symbol = i;
  }

  return root;
}

final TrieNode huffman_flat_decode_tables = buildHuffmanDecodeTrie();

/// ============================================================
/// QPACK static table (RFC 9204 Appendix A)
/// ============================================================

final List<List<String>> qpack_static_table_entries = <List<String>>[
  [":authority", ""],
  [":path", "/"],
  ["age", "0"],
  ["content-disposition", ""],
  ["content-length", "0"],
  ["cookie", ""],
  ["date", ""],
  ["etag", ""],
  ["if-modified-since", ""],
  ["if-none-match", ""],
  ["last-modified", ""],
  ["link", ""],
  ["location", ""],
  ["referer", ""],
  ["set-cookie", ""],
  [":method", "CONNECT"],
  [":method", "DELETE"],
  [":method", "GET"],
  [":method", "HEAD"],
  [":method", "OPTIONS"],
  [":method", "POST"],
  [":method", "PUT"],
  [":scheme", "http"],
  [":scheme", "https"],
  [":status", "103"],
  [":status", "200"],
  [":status", "304"],
  [":status", "404"],
  [":status", "503"],
  ["accept", "*/*"],
  ["accept", "application/dns-message"],
  ["accept-encoding", "gzip, deflate, br"],
  ["accept-ranges", "bytes"],
  ["access-control-allow-headers", "cache-control"],
  ["access-control-allow-headers", "content-type"],
  ["access-control-allow-origin", "*"],
  ["cache-control", "max-age=0"],
  ["cache-control", "max-age=2592000"],
  ["cache-control", "max-age=604800"],
  ["cache-control", "no-cache"],
  ["cache-control", "no-store"],
  ["cache-control", "public, max-age=31536000"],
  ["content-encoding", "br"],
  ["content-encoding", "gzip"],
  ["content-type", "application/dns-message"],
  ["content-type", "application/javascript"],
  ["content-type", "application/json"],
  ["content-type", "application/x-www-form-urlencoded"],
  ["content-type", "image/gif"],
  ["content-type", "image/jpeg"],
  ["content-type", "image/png"],
  ["content-type", "text/css"],
  ["content-type", "text/html; charset=utf-8"],
  ["content-type", "text/plain"],
  ["content-type", "text/plain;charset=utf-8"],
  ["range", "bytes=0-"],
  ["strict-transport-security", "max-age=31536000"],
  ["strict-transport-security", "max-age=31536000; includesubdomains"],
  ["strict-transport-security", "max-age=31536000; includesubdomains; preload"],
  ["vary", "accept-encoding"],
  ["vary", "origin"],
  ["x-content-type-options", "nosniff"],
  ["x-xss-protection", "1; mode=block"],
  [":status", "100"],
  [":status", "204"],
  [":status", "206"],
  [":status", "302"],
  [":status", "400"],
  [":status", "403"],
  [":status", "421"],
  [":status", "425"],
  [":status", "500"],
  ["accept-language", ""],
  ["access-control-allow-credentials", "FALSE"],
  ["access-control-allow-credentials", "TRUE"],
  ["access-control-allow-headers", "*"],
  ["access-control-allow-methods", "get"],
  ["access-control-allow-methods", "get, post, options"],
  ["access-control-allow-methods", "options"],
  ["access-control-expose-headers", "content-length"],
  ["access-control-request-headers", "content-type"],
  ["access-control-request-method", "get"],
  ["access-control-request-method", "post"],
  ["alt-svc", "clear"],
  ["authorization", ""],
  [
    "content-security-policy",
    "script-src 'none'; object-src 'none'; base-uri 'none'",
  ],
  ["early-data", "1"],
  ["expect-ct", ""],
  ["forwarded", ""],
  ["if-range", ""],
  ["origin", ""],
  ["purpose", "prefetch"],
  ["server", ""],
  ["timing-allow-origin", "*"],
  ["upgrade-insecure-requests", "1"],
  ["user-agent", ""],
  ["x-forwarded-for", ""],
  ["x-frame-options", "deny"],
  ["x-frame-options", "sameorigin"],
];

/// ============================================================
/// QPACK prefixed integer helpers
/// ============================================================

DecodeVarIntResult decodeVarInt(Uint8List buf, int prefixBits, int pos) {
  final maxPrefix = (1 << prefixBits) - 1;
  int byte = buf[pos];
  int value = byte & maxPrefix;
  pos++;

  if (value < maxPrefix) {
    return DecodeVarIntResult(value, pos);
  }

  int m = 0;
  while (true) {
    if (pos >= buf.length) {
      throw StateError('Unexpected end of buffer while decoding varint.');
    }

    byte = buf[pos++];
    value += (byte & 0x7f) << m;

    if ((byte & 0x80) == 0) break;
    m += 7;
  }

  return DecodeVarIntResult(value, pos);
}

Uint8List encodePrefixedInt(int value, int prefixBits, int prefixPattern) {
  final maxPrefix = (1 << prefixBits) - 1;
  final out = <int>[];

  if (value < maxPrefix) {
    out.add(prefixPattern | value);
    return Uint8List.fromList(out);
  }

  out.add(prefixPattern | maxPrefix);
  value -= maxPrefix;

  while (value >= 128) {
    out.add((value & 0x7f) | 0x80);
    value >>= 7;
  }
  out.add(value);

  return Uint8List.fromList(out);
}

/// ============================================================
/// Huffman encode / decode
/// ============================================================

Uint8List huffmanEncode(String text) {
  final input = utf8.encode(text);
  int bitBuffer = 0;
  int bitLen = 0;
  final output = <int>[];

  for (final sym in input) {
    final code = huffman_codes[sym];
    final nbits = huffman_bits[sym];

    bitBuffer = (bitBuffer << nbits) | code;
    bitLen += nbits;

    while (bitLen >= 8) {
      bitLen -= 8;
      output.add((bitBuffer >> bitLen) & 0xff);
    }
  }

  if (bitLen > 0) {
    bitBuffer = (bitBuffer << (8 - bitLen)) | ((1 << (8 - bitLen)) - 1);
    output.add(bitBuffer & 0xff);
  }

  return Uint8List.fromList(output);
}

int _bitAt(Uint8List buf, int bitIndex) {
  final byteIndex = bitIndex >> 3;
  final bitInByte = 7 - (bitIndex & 7);
  return (buf[byteIndex] >> bitInByte) & 1;
}

bool _trailingBitsAreAllOnes(Uint8List buf, int padLen) {
  if (padLen == 0) return true;
  final totalBits = buf.length * 8;
  final start = totalBits - padLen;

  for (int i = start; i < totalBits; i++) {
    if (_bitAt(buf, i) != 1) return false;
  }

  return true;
}

String? _decodeHuffmanExactBits(Uint8List buf, int totalBits) {
  final out = <int>[];
  var node = huffman_flat_decode_tables;

  for (int bitIndex = 0; bitIndex < totalBits; bitIndex++) {
    final bit = _bitAt(buf, bitIndex);
    node = (bit == 0)
        ? (node.zero ?? (throw StateError('Invalid Huffman')))
        : (node.one ?? (throw StateError('Invalid Huffman')));

    if (node.symbol != null) {
      if (node.symbol == 256) {
        // EOS symbol MUST NOT appear inside the decoded string.
        return null;
      }

      out.add(node.symbol!);
      node = huffman_flat_decode_tables;
    }
  }

  // Must end on a symbol boundary for the non-padding portion.
  if (!identical(node, huffman_flat_decode_tables)) {
    return null;
  }

  return utf8.decode(Uint8List.fromList(out));
}

String decodeHuffman(Uint8List buf) {
  final totalBits = buf.length * 8;

  // Padding in HPACK/QPACK Huffman is up to 7 bits of all 1s (EOS prefix).
  for (int padLen = 0; padLen <= 7 && padLen <= totalBits; padLen++) {
    if (!_trailingBitsAreAllOnes(buf, padLen)) continue;

    final decoded = _decodeHuffmanExactBits(buf, totalBits - padLen);
    if (decoded != null) return decoded;
  }

  throw StateError('Invalid Huffman encoding or padding.');
}

/// ============================================================
/// QPACK field section parsing / resolving
/// ============================================================

Map<String, dynamic> parse_qpack_header_block(Uint8List buf) {
  int pos = 0;
  final headers = <Map<String, dynamic>>[];

  // Required Insert Count (prefix-8)
  final ric = decodeVarInt(buf, 8, pos);
  pos = ric.next;

  // Delta Base (prefix-7) + Sign bit
  final firstDbByte = buf[pos];
  final postBase = (firstDbByte & 0x80) != 0; // S bit
  final db = decodeVarInt(buf, 7, pos);
  pos = db.next;

  final baseIndex = postBase ? (ric.value + db.value) : (ric.value - db.value);

  while (pos < buf.length) {
    final byte = buf[pos];

    // A. Indexed Field Line -- 1xxxxxxx
    if ((byte & 0x80) == 0x80) {
      final fromStatic = (byte & 0x40) != 0; // T bit
      final idx = decodeVarInt(buf, 6, pos);
      pos = idx.next;

      headers.add(<String, dynamic>{
        'type': 'indexed',
        'from_static_table': fromStatic,
        'index': idx.value,
      });
      continue;
    }

    // B. Literal Field Line With Name Reference -- 01xxxxxx
    if ((byte & 0xC0) == 0x40) {
      final neverIndexed = (byte & 0x20) != 0; // N bit
      final fromStatic = (byte & 0x10) != 0; // T bit
      final nameIdx = decodeVarInt(buf, 4, pos);
      pos = nameIdx.next;

      final valH = (buf[pos] & 0x80) != 0;
      final valLen = decodeVarInt(buf, 7, pos);
      pos = valLen.next;

      if (pos + valLen.value > buf.length) {
        throw StateError('Truncated QPACK literal value.');
      }

      final valBytes = buf.sublist(pos, pos + valLen.value);
      pos += valLen.value;

      final value = valH ? decodeHuffman(valBytes) : utf8.decode(valBytes);

      headers.add(<String, dynamic>{
        'type': 'literal_with_name_ref',
        'never_indexed': neverIndexed,
        'from_static_table': fromStatic,
        'name_index': nameIdx.value,
        'value': value,
      });
      continue;
    }

    // C. Literal Field Line With Literal Name -- 001xxxxx
    if ((byte & 0xE0) == 0x20) {
      final neverIndexed = (byte & 0x10) != 0; // N bit
      final nameH = (byte & 0x08) != 0; // H bit
      final nameLen = decodeVarInt(buf, 3, pos);
      pos = nameLen.next;

      if (pos + nameLen.value > buf.length) {
        throw StateError('Truncated QPACK literal name.');
      }

      final nameBytes = buf.sublist(pos, pos + nameLen.value);
      pos += nameLen.value;
      final name = nameH ? decodeHuffman(nameBytes) : utf8.decode(nameBytes);

      final valH = (buf[pos] & 0x80) != 0;
      final valLen = decodeVarInt(buf, 7, pos);
      pos = valLen.next;

      if (pos + valLen.value > buf.length) {
        throw StateError('Truncated QPACK literal value.');
      }

      final valBytes = buf.sublist(pos, pos + valLen.value);
      pos += valLen.value;
      final value = valH ? decodeHuffman(valBytes) : utf8.decode(valBytes);

      headers.add(<String, dynamic>{
        'type': 'literal_with_literal_name',
        'never_indexed': neverIndexed,
        'name': name,
        'value': value,
      });
      continue;
    }

    throw StateError(
      'Unknown QPACK header-block instruction at byte $pos '
      '(0x${byte.toRadixString(16)})',
    );
  }

  return <String, dynamic>{
    'insert_count': ric.value,
    'delta_base': db.value,
    'post_base': postBase,
    'base_index': baseIndex,
    'headers': headers,
  };
}

Map<String, dynamic> parse_qpack_header_block_old(Uint8List buf) {
  // Compatibility alias
  return parse_qpack_header_block(buf);
}

List<QpackHeaderField> resolveParsedQpackHeaderBlock(
  Map<String, dynamic> parsed,
) {
  final out = <QpackHeaderField>[];
  final headers = (parsed['headers'] as List<dynamic>);

  for (final item in headers) {
    final h = item as Map<String, dynamic>;
    final type = h['type'] as String;

    switch (type) {
      case 'indexed':
        final fromStatic = h['from_static_table'] == true;
        if (!fromStatic) {
          throw StateError(
            'Dynamic-table indexed fields are not supported yet.',
          );
        }

        final index = h['index'] as int;
        if (index < 0 || index >= qpack_static_table_entries.length) {
          throw StateError('Invalid QPACK static index: $index');
        }

        final entry = qpack_static_table_entries[index];
        out.add(QpackHeaderField(entry[0], entry[1]));
        break;

      case 'literal_with_name_ref':
        final fromStatic = h['from_static_table'] == true;
        if (!fromStatic) {
          throw StateError(
            'Dynamic-table name references are not supported yet.',
          );
        }

        final nameIndex = h['name_index'] as int;
        if (nameIndex < 0 || nameIndex >= qpack_static_table_entries.length) {
          throw StateError('Invalid QPACK static name index: $nameIndex');
        }

        final entry = qpack_static_table_entries[nameIndex];
        out.add(QpackHeaderField(entry[0], h['value'] as String));
        break;

      case 'literal_with_literal_name':
        out.add(QpackHeaderField(h['name'] as String, h['value'] as String));
        break;

      default:
        throw StateError('Unsupported QPACK representation type: $type');
    }
  }

  return out;
}

List<QpackHeaderField> decode_qpack_header_fields(Uint8List buf) {
  final parsed = parse_qpack_header_block(buf);
  return resolveParsedQpackHeaderBlock(parsed);
}

/// ============================================================
/// QPACK encoding (static-table-first, dynamic-table-free)
/// ============================================================

int? findExactStaticIndex(String name, String value) {
  for (int i = 0; i < qpack_static_table_entries.length; i++) {
    final entry = qpack_static_table_entries[i];
    if (entry[0] == name && entry[1] == value) {
      return i;
    }
  }
  return null;
}

int? findStaticNameIndex(String name) {
  for (int i = 0; i < qpack_static_table_entries.length; i++) {
    final entry = qpack_static_table_entries[i];
    if (entry[0] == name) {
      return i;
    }
  }
  return null;
}

Uint8List encodeQpackString(String text, {bool useHuffman = false}) {
  final bytes = useHuffman
      ? huffmanEncode(text)
      : Uint8List.fromList(utf8.encode(text));

  final lenBytes = encodePrefixedInt(bytes.length, 7, useHuffman ? 0x80 : 0x00);

  return Uint8List.fromList([...lenBytes, ...bytes]);
}

Uint8List buildQpackHeaderBlockStaticOrLiteral(
  List<QpackHeaderField> fields, {
  bool useHuffman = false,
}) {
  final out = <int>[];

  // Field Section Prefix:
  // Required Insert Count = 0
  // Delta Base = 0
  out.add(0x00);
  out.add(0x00);

  for (final field in fields) {
    final name = field.name.toLowerCase();
    final value = field.value;

    // 1) Exact static-table match -> Indexed Field Line
    final exactIndex = findExactStaticIndex(name, value);
    if (exactIndex != null) {
      // Indexed Field Line:
      // 1xxxxxxx with T=1 => 0xC0 prefix, 6-bit integer
      out.addAll(encodePrefixedInt(exactIndex, 6, 0xC0));
      continue;
    }

    // 2) Static name match -> Literal Field Line With Name Reference
    final nameIndex = findStaticNameIndex(name);
    if (nameIndex != null) {
      // 01xxxxxx with N=0, T=1 => 0x50 prefix, 4-bit integer
      out.addAll(encodePrefixedInt(nameIndex, 4, 0x50));
      out.addAll(encodeQpackString(value, useHuffman: useHuffman));
      continue;
    }

    // 3) Fallback -> Literal Field Line With Literal Name
    final nameBytes = useHuffman
        ? huffmanEncode(name)
        : Uint8List.fromList(utf8.encode(name));

    // 001xxxxx with N=0, H(name)=0/1 => prefix 0x20 or 0x28, 3-bit integer
    final namePrefix = useHuffman ? 0x28 : 0x20;
    final nameLenEnc = encodePrefixedInt(nameBytes.length, 3, namePrefix);

    out.addAll(nameLenEnc);
    out.addAll(nameBytes);
    out.addAll(encodeQpackString(value, useHuffman: useHuffman));
  }

  return Uint8List.fromList(out);
}

/// Backward-compatible name kept from your original file.
/// Returns a QPACK field section payload (not an HTTP/3 frame wrapper).
Uint8List build_http3_literal_headers_frame(
  Map<String, Object?> headers, {
  bool useHuffman = false,
}) {
  final fields = <QpackHeaderField>[];

  headers.forEach((key, value) {
    fields.add(QpackHeaderField(key.toLowerCase(), '${value ?? ''}'));
  });

  return buildQpackHeaderBlockStaticOrLiteral(fields, useHuffman: useHuffman);
}

/// ============================================================
/// HTTP/3 frame helpers
/// ============================================================

List<int> _sortedChunkOffsets(Map<int, Uint8List> chunks) {
  final offsets = chunks.keys.toList()..sort();
  return offsets;
}

Uint8List _combineChunksFromOffset(Map<int, Uint8List> chunks, int fromOffset) {
  final offsets = _sortedChunkOffsets(chunks);
  final buffers = <Uint8List>[];

  for (int i = 0; i < offsets.length; i++) {
    final base = offsets[i];
    final chunk = chunks[base]!;

    if (fromOffset >= base && fromOffset < base + chunk.length) {
      final start = fromOffset - base;
      buffers.add(chunk.sublist(start));

      for (int j = i + 1; j < offsets.length; j++) {
        buffers.add(chunks[offsets[j]]!);
      }
      break;
    }
  }

  if (buffers.isEmpty) {
    return Uint8List(0);
  }

  return concatUint8Lists(buffers);
}

void _removeConsumedBytesFromChunks(
  Map<int, Uint8List> chunks,
  int fromOffset,
  int consumedBytes,
) {
  if (consumedBytes <= 0) return;

  final offsets = _sortedChunkOffsets(chunks);
  final newChunks = <int, Uint8List>{};
  int bytesLeft = consumedBytes;
  int currentOffset = fromOffset;

  for (final base in offsets) {
    final chunk = chunks[base]!;

    if (currentOffset >= base + chunk.length) {
      continue;
    }

    final relStart = (currentOffset - base).clamp(0, chunk.length);
    final relEnd = (currentOffset + bytesLeft - base).clamp(0, chunk.length);

    if (relEnd < chunk.length) {
      final leftover = chunk.sublist(relEnd);
      newChunks[base + relEnd] = leftover;
    }

    bytesLeft -= (relEnd - relStart);
    if (bytesLeft <= 0) break;
  }

  chunks
    ..clear()
    ..addAll(newChunks);
}

Map<String, dynamic> extract_h3_frames_from_chunks(
  Map<int, Uint8List> chunks,
  int from_offset,
) {
  final combined = _combineChunksFromOffset(chunks, from_offset);
  if (combined.isEmpty) {
    return <String, dynamic>{
      'frames': <Map<String, dynamic>>[],
      'new_from_offset': from_offset,
    };
  }

  int offset = 0;
  final frames = <Map<String, dynamic>>[];

  dynamic safeReadVarInt() {
    if (offset >= combined.length) return null;
    final dynamic res = readVarInt(combined, offset);
    if (res == null) return null;
    offset += res.byteLength as int;
    return res;
  }

  while (offset < combined.length) {
    final startOffset = offset;

    final dynamic frameType = safeReadVarInt();
    if (frameType == null) break;

    final dynamic lengthInfo = safeReadVarInt();
    if (lengthInfo == null) {
      offset = startOffset; // rollback
      break;
    }

    final payloadLength = lengthInfo.value as int;
    if (offset + payloadLength > combined.length) {
      offset = startOffset; // rollback
      break;
    }

    final payload = combined.sublist(offset, offset + payloadLength);
    frames.add(<String, dynamic>{
      'frame_type': frameType.value as int,
      'payload': payload,
    });

    offset += payloadLength;
  }

  if (offset > 0) {
    _removeConsumedBytesFromChunks(chunks, from_offset, offset);
    from_offset += offset;
  }

  return <String, dynamic>{'frames': frames, 'new_from_offset': from_offset};
}

Uint8List build_h3_frames(List<Map<String, dynamic>> frames) {
  final parts = <Uint8List>[];

  for (final frame in frames) {
    final int frameType = frame['frame_type'] as int;
    final Uint8List payload = frame['payload'] as Uint8List;

    final typeBytes = writeVarInt(frameType);
    final lenBytes = writeVarInt(payload.length);

    parts.addAll(<Uint8List>[typeBytes, lenBytes, payload]);
  }

  return concatUint8Lists(parts);
}

/// ============================================================
/// QPACK encoder stream instruction parsing
/// ============================================================

int? computeVarIntLen(Uint8List buf, int pos, int prefixBits) {
  if (pos >= buf.length) return null;

  final first = buf[pos];
  final prefixMask = (1 << prefixBits) - 1;
  final prefixVal = first & prefixMask;

  if (prefixVal < prefixMask) return 1;

  int len = 1;
  int idx = pos + 1;

  while (idx < buf.length) {
    len++;
    if ((buf[idx] & 0x80) == 0) return len;
    idx++;
  }

  return null;
}

int? safeDecodePrefixedVarInt(Uint8List buf, _PosRef posRef, int prefixBits) {
  final len = computeVarIntLen(buf, posRef.pos, prefixBits);
  if (len == null) return null;

  final res = decodeVarInt(buf, prefixBits, posRef.pos);
  posRef.pos = res.next;
  return res.value;
}

Map<String, dynamic> extract_qpack_encoder_instructions_from_chunks(
  Map<int, Uint8List> chunks,
  int from_offset,
) {
  final combined = _combineChunksFromOffset(chunks, from_offset);
  if (combined.isEmpty) {
    return <String, dynamic>{
      'instructions': <Map<String, dynamic>>[],
      'new_from_offset': from_offset,
    };
  }

  final posRef = _PosRef(0);
  final instructions = <Map<String, dynamic>>[];

  while (posRef.pos < combined.length) {
    final startPos = posRef.pos;
    final byte = combined[posRef.pos];

    // A. Insert With Name Reference -- 1xxxxxxx
    if ((byte & 0x80) == 0x80) {
      final fromStatic = (byte & 0x40) != 0;
      final nameIdx = safeDecodePrefixedVarInt(combined, posRef, 6);
      if (nameIdx == null) break;

      if (posRef.pos >= combined.length) {
        posRef.pos = startPos;
        break;
      }

      final valHuffman = (combined[posRef.pos] & 0x80) != 0;
      final valLen = safeDecodePrefixedVarInt(combined, posRef, 7);
      if (valLen == null || posRef.pos + valLen > combined.length) {
        posRef.pos = startPos;
        break;
      }

      final valBytes = combined.sublist(posRef.pos, posRef.pos + valLen);
      posRef.pos += valLen;

      final value = valHuffman
          ? decodeHuffman(valBytes)
          : utf8.decode(valBytes);

      instructions.add(<String, dynamic>{
        'type': 'insert_with_name_ref',
        'from_static_table': fromStatic,
        'name_index': nameIdx,
        'value': value,
      });
      continue;
    }

    // B. Insert Without Name Reference -- 01xxxxxx
    if ((byte & 0xC0) == 0x40) {
      final nameH = (byte & 0x20) != 0;
      final nameLen = safeDecodePrefixedVarInt(combined, posRef, 5);
      if (nameLen == null || posRef.pos + nameLen > combined.length) {
        posRef.pos = startPos;
        break;
      }

      final nameBytes = combined.sublist(posRef.pos, posRef.pos + nameLen);
      posRef.pos += nameLen;

      if (posRef.pos >= combined.length) {
        posRef.pos = startPos;
        break;
      }

      final valH = (combined[posRef.pos] & 0x80) != 0;
      final valLen = safeDecodePrefixedVarInt(combined, posRef, 7);
      if (valLen == null || posRef.pos + valLen > combined.length) {
        posRef.pos = startPos;
        break;
      }

      final valBytes = combined.sublist(posRef.pos, posRef.pos + valLen);
      posRef.pos += valLen;

      final name = nameH ? decodeHuffman(nameBytes) : utf8.decode(nameBytes);
      final value = valH ? decodeHuffman(valBytes) : utf8.decode(valBytes);

      instructions.add(<String, dynamic>{
        'type': 'insert_without_name_ref',
        'name': name,
        'value': value,
      });
      continue;
    }

    // C. Set Dynamic Table Capacity -- 001xxxxx
    if ((byte & 0xE0) == 0x20) {
      final capacity = safeDecodePrefixedVarInt(combined, posRef, 5);
      if (capacity == null) {
        posRef.pos = startPos;
        break;
      }

      instructions.add(<String, dynamic>{
        'type': 'set_dynamic_table_capacity',
        'capacity': capacity,
      });
      continue;
    }

    // D. Duplicate -- 0000xxxx
    if ((byte & 0xF0) == 0x00) {
      final dupIndex = safeDecodePrefixedVarInt(combined, posRef, 4);
      if (dupIndex == null) {
        posRef.pos = startPos;
        break;
      }

      instructions.add(<String, dynamic>{
        'type': 'duplicate',
        'index': dupIndex,
      });
      continue;
    }

    // Unknown / incomplete
    break;
  }

  final consumed = posRef.pos;

  if (consumed > 0) {
    _removeConsumedBytesFromChunks(chunks, from_offset, consumed);
    from_offset += consumed;
  }

  return <String, dynamic>{
    'instructions': instructions,
    'new_from_offset': from_offset,
  };
}

/// ============================================================
/// HTTP/3 SETTINGS
/// ============================================================

const List<List<dynamic>> h3_settings_frame_params = <List<dynamic>>[
  [0x01, "SETTINGS_QPACK_MAX_TABLE_CAPACITY"],
  [0x06, "SETTINGS_MAX_FIELD_SECTION_SIZE"],
  [0x07, "SETTINGS_QPACK_BLOCKED_STREAMS"],
  [0x08, "SETTINGS_ENABLE_CONNECT_PROTOCOL"],
  [0x33, "SETTINGS_H3_DATAGRAM"],
  [0x2b603742, "SETTINGS_ENABLE_WEBTRANSPORT"],
  [0x0d, "SETTINGS_NO_RFC9114_LEGACY_CODEPOINT"],
  [0x14E9CD29, "SETTINGS_WT_MAX_SESSIONS"],
  [0x4d44, "SETTINGS_ENABLE_METADATA"],
];

final Map<String, int> h3_name_to_id = <String, int>{};
final Map<int, String> h3_id_to_name = <int, String>{};

void _initH3SettingsMaps() {
  if (h3_name_to_id.isNotEmpty) return;

  for (final entry in h3_settings_frame_params) {
    final id = entry[0] as int;
    final name = entry[1] as String;
    h3_name_to_id[name] = id;
    h3_id_to_name[id] = name;
  }
}

Map<String, int> parse_h3_settings_frame(Uint8List buf) {
  _initH3SettingsMaps();

  final settings = <String, int>{};
  int offset = 0;

  while (offset < buf.length) {
    final dynamic idRes = readVarInt(buf, offset);
    if (idRes == null) break;
    offset += idRes.byteLength as int;

    final dynamic valRes = readVarInt(buf, offset);
    if (valRes == null) break;
    offset += valRes.byteLength as int;

    final id = idRes.value as int;
    final value = valRes.value as int;

    final name = h3_id_to_name[id] ?? 'UNKNOWN_0x${id.toRadixString(16)}';
    settings[name] = value;
  }

  return settings;
}

Uint8List build_settings_frame(Map<String, int> settings_named) {
  _initH3SettingsMaps();

  final framePayload = <int>[];

  for (final entry in settings_named.entries) {
    final id = h3_name_to_id[entry.key];
    if (id == null) {
      throw StateError('Unknown setting name: ${entry.key}');
    }

    framePayload.addAll(writeVarInt(id));
    framePayload.addAll(writeVarInt(entry.value));
  }

  return Uint8List.fromList(framePayload);
}

Uint8List build_control_stream(Map<String, int> settings_named) {
  final payload = build_settings_frame(settings_named);

  return Uint8List.fromList([
    ...writeVarInt(0x00), // control stream type
    ...writeVarInt(0x04), // SETTINGS frame type
    ...writeVarInt(payload.length),
    ...payload,
  ]);
}

Uint8List build_control_stream_old(Map<String, int> settings_named) {
  // Compatibility alias
  return build_control_stream(settings_named);
}

/// ============================================================
/// Misc helpers kept for compatibility
/// ============================================================

List<int> encodeInt(int value, int prefixBits) {
  final max = (1 << prefixBits) - 1;
  if (value < max) return <int>[value];

  final bytes = <int>[max];
  value -= max;

  while (value >= 128) {
    bytes.add((value & 0x7F) | 0x80);
    value >>= 7;
  }

  bytes.add(value);
  return bytes;
}

Uint8List encodeStringLiteral(Uint8List bytes, int hFlag) {
  final lenBytes = encodeInt(bytes.length, 7);
  lenBytes[0] |= (hFlag << 7);

  return Uint8List.fromList([...lenBytes, ...bytes]);
}

/// ============================================================
/// QPACK decoder stream helpers (dynamic-table path; kept as helpers)
/// ============================================================

Uint8List build_qpack_block_header_ack(int stream_id) {
  return concatUint8Lists([
    Uint8List.fromList([0x81]),
    writeVarInt(stream_id),
  ]);
}

Uint8List? build_qpack_known_received_count(int count) {
  if (count <= 0) return null;

  final buf = writeVarInt(count);
  if (buf.isNotEmpty) {
    buf[0] &= 0x3F;
  }
  return buf;
}

/// ============================================================
/// WebTransport DATAGRAM payload helper
/// ============================================================

Map<String, dynamic> parse_webtransport_datagram(Uint8List payload) {
  final dynamic result = readVarInt(payload, 0);
  if (result == null) {
    throw StateError('Invalid VarInt at beginning of payload');
  }

  final int streamId = result.value as int;
  final int prefixLen = result.byteLength as int;
  final Uint8List data = payload.sublist(prefixLen);

  return <String, dynamic>{'stream_id': streamId, 'data': data};
}
