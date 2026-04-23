import 'dart:typed_data';

class QuicStreamReassembler {
  // Next unread byte offset
  int readOffset = 0;

  // Buffered chunks keyed by offset
  final Map<int, Uint8List> _chunks = {};

  /// Insert a received stream chunk.
  /// Safe to call multiple times with retransmissions.
  void insert(int offset, Uint8List data) {
    // Discard data we've already consumed
    if (offset + data.length <= readOffset) {
      return;
    }

    // Trim front if partially consumed
    if (offset < readOffset) {
      final trim = readOffset - offset;
      data = data.sublist(trim);
      offset = readOffset;
    }

    // Ignore duplicate chunk
    if (_chunks.containsKey(offset)) {
      return;
    }

    _chunks[offset] = data;
  }

  /// Drain all contiguous bytes starting at readOffset.
  /// Returns empty Uint8List if nothing is ready.
  Uint8List drain() {
    if (!_chunks.containsKey(readOffset)) {
      return Uint8List(0);
    }

    final out = BytesBuilder();

    while (true) {
      final chunk = _chunks.remove(readOffset);
      if (chunk == null) break;

      out.add(chunk);
      readOffset += chunk.length;
    }

    return out.toBytes();
  }

  /// Hard reset (rarely needed, but useful on stream close)
  void clear() {
    _chunks.clear();
    readOffset = 0;
  }
}