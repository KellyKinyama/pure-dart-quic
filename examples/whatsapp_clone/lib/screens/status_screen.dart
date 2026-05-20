import 'package:flutter/material.dart';
import '../theme.dart';

class StatusScreen extends StatelessWidget {
  const StatusScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return ListView(
      children: const [
        ListTile(
          leading: CircleAvatar(
            radius: 28,
            backgroundColor: WaTheme.primary,
            child: Icon(Icons.add, color: Colors.white),
          ),
          title: Text(
            'My status',
            style: TextStyle(fontWeight: FontWeight.w600),
          ),
          subtitle: Text('Tap to add status update'),
        ),
        Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'Recent updates',
            style: TextStyle(color: Colors.black54, fontSize: 13),
          ),
        ),
        Center(
          child: Padding(
            padding: EdgeInsets.all(24),
            child: Text('No recent updates.'),
          ),
        ),
      ],
    );
  }
}
