// Filename: buffer.dart
import 'dart:math';
import 'dart:typed_data';

class BufferReadError implements Exception {
  final String message;
  BufferReadError(this.message);
  @override
  String toString() => 'BufferReadError: $message';
}

class BufferWriteError implements Exception {
  final String message;
  BufferWriteError(this.message);
  @override
  String toString() => 'BufferWriteError: $message';
}

/// An extension to add the missing setUint24 method to ByteData.
extension ByteDataWriter on ByteData {
  void setUint24(int offset, int value) {
    setUint8(offset, (value >> 16) & 0xFF);
    setUint8(offset + 1, (value >> 8) & 0xFF);
    setUint8(offset + 2, value & 0xFF);
  }
}

/// A simple buffer to read data sequentially from a Uint8List.
class QuicBuffer {
  ByteData _byteData;
  int _readOffset = 0;
  int _writeIndex = 0;

  int get length => _byteData.lengthInBytes;
  bool get eof => _readOffset >= length;
  int get remaining => length - _readOffset;
  ByteData get byteData => _byteData;
  int get readOffset => _readOffset;
  int get writeIndex => _writeIndex;
  Uint8List get data => _byteData.buffer.asUint8List(0);

  /// The total capacity of the buffer.
  int get capacity => _byteData.lengthInBytes;

  Uint8List toBytes() {
    return _byteData.buffer.asUint8List(0, _writeIndex);
  }

  // Buffer({required Uint8List data, int capacity = 0})
  //   : _byteData = data.buffer.asByteData(
  //       data.offsetInBytes,
  //       data.lengthInBytes,
  //     );

  // CORRECTED CONSTRUCTOR
  QuicBuffer({Uint8List? data})
    : _byteData = data != null
          ? data.buffer.asByteData(data.offsetInBytes, data.lengthInBytes)
          : ByteData(0), // If data is null, create an empty ByteData object
      _writeIndex = data?.length ?? 0;

  int pullUint8() {
    final v = _byteData.getUint8(_readOffset);
    _readOffset += 1;
    return v;
  }

  int pullUint16() {
    final v = _byteData.getUint16(_readOffset);
    _readOffset += 2;
    return v;
  }

  int pullUint24() {
    final h = pullUint8();
    final l = pullUint16();
    return (h << 16) | l;
  }

  void pushUint24(int value) {
    pushUint8(value & 0xFF);
    pushUint8((value >> 8) & 0xFF);
    pushUint8((value >> 16) & 0xFF);
    //  ..[0] = (value >> 16) & 0xFF
    //     ..[1] = (value >> 8) & 0xFF
    //     ..[2] = value & 0xFF;
  }

  int pullUint32() {
    final v = _byteData.getUint32(_readOffset);
    _readOffset += 4;
    return v;
  }

  int getUint32() {
    final v = _byteData.getUint32(_readOffset);
    _readOffset += 4;
    return v;
  }

  Uint8List pullBytes(int len) {
    if (_readOffset + len > length) {
      // throw Exception('Buffer underflow at readoffset: $_readOffset');
      throw BufferReadError(
        'Cannot pull $length bytes, only $remaining available',
      );
    }
    final b = _byteData.buffer.asUint8List(
      _byteData.offsetInBytes + _readOffset,
      len,
    );
    _readOffset += len;
    return b;
  }

  Uint8List viewBytes(int length, {int offset = 0}) {
    if (remaining < length) {
      throw BufferReadError(
        'Cannot view $length bytes, only $remaining available',
      );
    }
    // _readOffset = length;
    return _byteData.buffer.asUint8List(_readOffset + offset, length);
  }

  Uint8List pullVector(int lenBytes) {
    int vecLen;
    if (lenBytes == 1) {
      vecLen = pullUint8();
    } else if (lenBytes == 2) {
      vecLen = pullUint16();
    } else if (lenBytes == 3) {
      vecLen = pullUint24();
    } else {
      throw ArgumentError('Vector length must be 1, 2, or 3 bytes');
    }
    return pullBytes(vecLen);
  }

  void pushVector(Uint8List bytes, int lenBytes) {
    int vecLen = bytes.length;
    if (lenBytes == 1) {
      pushUint8(vecLen);
    } else if (lenBytes == 2) {
      pushUint16(vecLen);
    } else if (lenBytes == 3) {
      pushUint24(vecLen);
    } else {
      throw ArgumentError('Vector length must be 1, 2, or 3 bytes');
    }
    pushBytes(bytes);
  }

  int pullVarInt() {
    final firstByte = _byteData.getUint8(_readOffset);
    final prefix = firstByte >> 6;
    final len = 1 << prefix;
    if (_readOffset + len > length) {
      throw Exception('VarInt read would overflow buffer');
    }
    int val = firstByte & 0x3F;
    for (int i = 1; i < len; i++) {
      val = (val << 8) | _byteData.getUint8(_readOffset + i);
    }
    _readOffset += len;
    return val;
  }

  /// The current read position.
  int tell() => _readOffset;

  int position({int? offset}) {
    if (offset != null) _readOffset = offset;
    return tell();
  }

  void _ensureCapacity(int needed) {
    if (capacity - _writeIndex < needed) {
      final newCapacity = max(capacity * 2, _writeIndex + needed);
      final newByteData = ByteData(newCapacity);
      final newBytes = newByteData.buffer.asUint8List();
      newBytes.setRange(0, _writeIndex, data);
      _byteData = newByteData;
    }
  }

  void pushBytes(Uint8List bytes) {
    _ensureCapacity(bytes.length);
    _byteData.buffer.asUint8List().setRange(
      _writeIndex,
      _writeIndex + bytes.length,
      bytes,
    );
    _writeIndex += bytes.length;
  }

  void pushUint8(int value) {
    _ensureCapacity(1);
    _byteData.setUint8(_writeIndex, value);
    _writeIndex++;
  }

  void pushUint16(int value) {
    _ensureCapacity(2);
    _byteData.setUint16(_writeIndex, value, Endian.big);
    _writeIndex += 2;
  }

  void pushUint32(int value) {
    _ensureCapacity(4);
    _byteData.setUint32(_writeIndex, value, Endian.big);
    _writeIndex += 4;
  }

  // CORRECTION 4: Fix for 8-byte (64-bit) var-int encoding
  void pushVarint(int value) {
    if (value < 0x40) {
      // 1-byte
      _ensureCapacity(1);
      pushUint8(0x00 | value);
    } else if (value < 0x4000) {
      // 2-byte
      _ensureCapacity(2);
      pushUint16(0x4000 | value);
    } else if (value < 0x40000000) {
      // 4-byte
      _ensureCapacity(4);
      pushUint32(0x80000000 | value);
    } else if (value < 0x4000000000000000) {
      // 8-byte
      _ensureCapacity(8);
      // Use setUint64 for proper 8-byte integer handling
      _byteData.setUint64(_writeIndex, 0xC000000000000000 | value, Endian.big);
      _writeIndex += 8;
    } else {
      throw ArgumentError('Value too large for QUIC var-int');
    }
  }
}
