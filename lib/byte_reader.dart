import 'dart:typed_data';

class ByteReader {
  final Uint8List _data;
  int _off = 0;

  ByteReader(this._data) {
    print("[DEBUG] ByteReader created with ${_data.length} bytes");
  }

  int get remaining => _data.length - _off;

  // int get offset => null;

  Uint8List peek(int n) {
    print("[DEBUG] peek($n) at offset $_off remaining=$remaining");
    if (remaining < n) throw StateError('Need more data to peek $n bytes.');
    return _data.sublist(_off, _off + n);
  }

  Uint8List readBytes(int n) {
    print("[DEBUG] readBytes($n) at offset $_off remaining=$remaining");
    if (remaining < n)
      throw StateError('Need more data: wanted $n bytes, have $remaining.');
    final out = _data.sublist(_off, _off + n);
    _off += n;
    return out;
  }

  int readUint8() {
    final v = readBytes(1)[0];
    print("[DEBUG] readUint8 -> $v");
    return v;
  }

  int readInt8() {
    final v = readUint8();
    return v >= 0x80 ? v - 0x100 : v;
  }

  int readUint16be() {
    final bytes = readBytes(2);
    final value = ByteData.sublistView(bytes).getUint16(0, Endian.big);
    print("[DEBUG] readUint16be -> 0x${value.toRadixString(16)}");
    return value;
  }

  int readInt16be() {
    final bytes = readBytes(2);
    final value = ByteData.sublistView(bytes).getInt16(0, Endian.big);
    print("[DEBUG] readInt16be -> $value");
    return value;
  }

  void offset(int i) {
    _off = _off - i;
  }

  int peekUint8() {
    if (remaining < 1) {
      throw StateError('EOF');
    }
    return _data[_off];
  }
}
