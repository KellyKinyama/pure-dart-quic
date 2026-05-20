// Fullscreen call UI driven by CallService.

import 'package:flutter/material.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:provider/provider.dart';

import '../models/call.dart';
import '../services/call_service.dart';
import '../services/xmpp_service.dart';
import '../theme.dart';
import '../widgets/avatar.dart';

class CallScreen extends StatelessWidget {
  const CallScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final call = context.watch<CallService>();
    final xmpp = context.read<XmppService>();
    final c = call.active;
    if (c == null) {
      // Defensive: pop if state evaporated.
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (Navigator.canPop(context)) Navigator.pop(context);
      });
      return const SizedBox.shrink();
    }
    final contact = xmpp.contacts[c.peerId];
    final name = contact?.name ?? c.peerId;
    final stateLabel = _stateLabel(c);

    return PopScope(
      canPop: false,
      child: Scaffold(
        backgroundColor: Colors.black,
        body: SafeArea(
          child: Stack(
            children: [
              // Remote video fills the screen (audio call -> dark background).
              if (c.video)
                Positioned.fill(
                  child: RTCVideoView(
                    call.remoteRenderer,
                    objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitCover,
                  ),
                )
              else
                const Positioned.fill(child: ColoredBox(color: Colors.black)),

              // Big avatar for audio-only / pre-connect state.
              if (!c.video || c.state != CallState.connected)
                Positioned.fill(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      WaAvatar(name: name, size: 96, online: false),
                      const SizedBox(height: 16),
                      Text(
                        name,
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 22,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        stateLabel,
                        style: const TextStyle(
                          color: Colors.white70,
                          fontSize: 14,
                        ),
                      ),
                    ],
                  ),
                ),

              // Local PiP (top-right) when video.
              if (c.video)
                Positioned(
                  top: 12,
                  right: 12,
                  width: 110,
                  height: 160,
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(12),
                    child: RTCVideoView(
                      call.localRenderer,
                      mirror: call.frontCamera,
                      objectFit:
                          RTCVideoViewObjectFit.RTCVideoViewObjectFitCover,
                    ),
                  ),
                ),

              // Top bar.
              Positioned(
                top: 12,
                left: 12,
                child: Text(
                  c.video ? 'Video call' : 'Voice call',
                  style: const TextStyle(color: Colors.white70),
                ),
              ),

              // Bottom control rail.
              Positioned(
                left: 0,
                right: 0,
                bottom: 24,
                child: _ControlRail(call: call),
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _stateLabel(ActiveCall c) {
    switch (c.state) {
      case CallState.dialing:
        return 'Calling…';
      case CallState.ringing:
        return c.direction == CallDirection.incoming
            ? 'Incoming call'
            : 'Ringing…';
      case CallState.connecting:
        return 'Connecting…';
      case CallState.connected:
        final start = c.connectedAt;
        if (start == null) return 'Connected';
        final d = DateTime.now().difference(start);
        final mm = d.inMinutes.remainder(60).toString().padLeft(2, '0');
        final ss = d.inSeconds.remainder(60).toString().padLeft(2, '0');
        return '$mm:$ss';
      case CallState.ended:
        return 'Call ended${c.endReason != null ? ' (${c.endReason})' : ''}';
      default:
        return '';
    }
  }
}

class _ControlRail extends StatelessWidget {
  final CallService call;
  const _ControlRail({required this.call});

  @override
  Widget build(BuildContext context) {
    final c = call.active!;
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        _Btn(
          icon: call.micMuted ? Icons.mic_off : Icons.mic,
          color: call.micMuted ? Colors.white24 : Colors.white24,
          iconColor: Colors.white,
          onTap: call.toggleMic,
        ),
        const SizedBox(width: 16),
        if (c.video)
          _Btn(
            icon: call.cameraOff ? Icons.videocam_off : Icons.videocam,
            color: Colors.white24,
            iconColor: Colors.white,
            onTap: call.toggleCamera,
          )
        else
          _Btn(
            icon: call.speakerOn ? Icons.volume_up : Icons.volume_down,
            color: Colors.white24,
            iconColor: Colors.white,
            onTap: call.toggleSpeaker,
          ),
        const SizedBox(width: 16),
        if (c.video)
          _Btn(
            icon: Icons.cameraswitch,
            color: Colors.white24,
            iconColor: Colors.white,
            onTap: call.switchCamera,
          ),
        if (c.video) const SizedBox(width: 16),
        _Btn(
          icon: Icons.call_end,
          color: WaTheme.danger,
          iconColor: Colors.white,
          onTap: () => call.endCall(),
        ),
      ],
    );
  }
}

class _Btn extends StatelessWidget {
  final IconData icon;
  final Color color;
  final Color iconColor;
  final VoidCallback onTap;
  const _Btn({
    required this.icon,
    required this.color,
    required this.iconColor,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return Material(
      color: color,
      shape: const CircleBorder(),
      child: InkWell(
        customBorder: const CircleBorder(),
        onTap: onTap,
        child: SizedBox(
          width: 60,
          height: 60,
          child: Icon(icon, color: iconColor, size: 28),
        ),
      ),
    );
  }
}
