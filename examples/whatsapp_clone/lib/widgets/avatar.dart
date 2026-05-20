import 'package:flutter/material.dart';

import '../theme.dart';

class WaAvatar extends StatelessWidget {
  final String name;
  final bool online;
  final double size;
  const WaAvatar({
    super.key,
    required this.name,
    this.online = false,
    this.size = 44,
  });

  Color _bg() {
    final h = name.hashCode;
    const palette = <Color>[
      WaTheme.primary,
      WaTheme.secondary,
      Color(0xFF34B7F1),
      Color(0xFFA66BBE),
      Color(0xFFE57373),
      Color(0xFFFFB300),
    ];
    return palette[h.abs() % palette.length];
  }

  @override
  Widget build(BuildContext context) {
    final letter = name.isEmpty ? '?' : name.trim()[0].toUpperCase();
    return SizedBox(
      width: size,
      height: size,
      child: Stack(
        children: [
          CircleAvatar(
            radius: size / 2,
            backgroundColor: _bg(),
            child: Text(
              letter,
              style: TextStyle(
                color: Colors.white,
                fontSize: size * 0.42,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          if (online)
            Positioned(
              right: 0,
              bottom: 0,
              child: Container(
                width: size * 0.28,
                height: size * 0.28,
                decoration: BoxDecoration(
                  color: WaTheme.accent,
                  shape: BoxShape.circle,
                  border: Border.all(color: Colors.white, width: 2),
                ),
              ),
            ),
        ],
      ),
    );
  }
}
