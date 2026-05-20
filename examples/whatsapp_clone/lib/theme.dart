// WhatsApp-clone theme tokens.

import 'package:flutter/material.dart';

class WaTheme {
  static const Color primary = Color(0xFF075E54);
  static const Color secondary = Color(0xFF128C7E);
  static const Color accent = Color(0xFF25D366);
  static const Color tealLight = Color(0xFFDCF8C6);
  static const Color bgChat = Color(0xFFECE5DD);
  static const Color msgIn = Colors.white;
  static const Color msgOut = Color(0xFFDCF8C6);
  static const Color danger = Color(0xFFE53935);

  static ThemeData light() {
    final base = ThemeData.light(useMaterial3: false);
    return base.copyWith(
      primaryColor: primary,
      colorScheme: base.colorScheme.copyWith(
        primary: primary,
        secondary: accent,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: primary,
        foregroundColor: Colors.white,
        elevation: 1,
      ),
      tabBarTheme: const TabBarThemeData(
        labelColor: Colors.white,
        unselectedLabelColor: Colors.white70,
        indicatorColor: Colors.white,
      ),
      floatingActionButtonTheme: const FloatingActionButtonThemeData(
        backgroundColor: accent,
        foregroundColor: Colors.white,
      ),
      scaffoldBackgroundColor: Colors.white,
    );
  }
}
