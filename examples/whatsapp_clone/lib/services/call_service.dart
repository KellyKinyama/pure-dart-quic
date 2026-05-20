// CallService — 1-to-1 audio/video calling via flutter_webrtc, signaled
// over the XmppService's <call-*> stanzas.
//
// Architecture:
//   * One CallService instance, shared via Provider.
//   * Subscribes to xmpp.callSignals as soon as it's bound.
//   * State lives in `_activeCall` (only one call at a time).
//   * Local & remote RTCVideoRenderers are exposed for the UI.
//
// NOTE: this uses flutter_webrtc (native libwebrtc) for capture + render.
// pure_dart_webrtc could be plugged in on the server side as a recorder
// or SFU peer, but for 1-to-1 P2P the server only relays signaling.

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:permission_handler/permission_handler.dart';

import '../models/call.dart';
import 'xmpp_service.dart';

class ActiveCall {
  final String id;
  final String peerId;
  final bool video;
  final CallDirection direction;
  CallState state;
  String? endReason;
  DateTime? connectedAt;

  ActiveCall({
    required this.id,
    required this.peerId,
    required this.video,
    required this.direction,
    this.state = CallState.idle,
  });
}

class CallService extends ChangeNotifier {
  final XmppService xmpp;
  StreamSubscription<CallSignal>? _sub;

  ActiveCall? _active;
  ActiveCall? get active => _active;

  RTCPeerConnection? _pc;
  MediaStream? _localStream;
  MediaStream? _remoteStream;

  final RTCVideoRenderer localRenderer = RTCVideoRenderer();
  final RTCVideoRenderer remoteRenderer = RTCVideoRenderer();
  bool _renderersReady = false;

  // ICE candidates that arrive before remote description is set need
  // to be queued.
  final List<RTCIceCandidate> _pendingRemoteIce = <RTCIceCandidate>[];

  bool _micMuted = false;
  bool get micMuted => _micMuted;
  bool _cameraOff = false;
  bool get cameraOff => _cameraOff;
  bool _speakerOn = true;
  bool get speakerOn => _speakerOn;
  bool _frontCamera = true;
  bool get frontCamera => _frontCamera;

  CallService(this.xmpp) {
    _sub = xmpp.callSignals.listen(_onSignal);
  }

  @override
  void dispose() {
    _sub?.cancel();
    _teardown();
    localRenderer.dispose();
    remoteRenderer.dispose();
    super.dispose();
  }

  Future<void> _ensureRenderers() async {
    if (_renderersReady) return;
    await localRenderer.initialize();
    await remoteRenderer.initialize();
    _renderersReady = true;
  }

  // -------------------------------------------------------------------
  // Outgoing call
  // -------------------------------------------------------------------
  Future<void> startCall(String peerId, {required bool video}) async {
    if (_active != null) return; // busy
    if (!await _requestPermissions(video: video)) return;
    final id = xmpp.newCallId();
    _active = ActiveCall(
      id: id,
      peerId: peerId,
      video: video,
      direction: CallDirection.outgoing,
      state: CallState.dialing,
    );
    notifyListeners();
    try {
      await _ensureRenderers();
      await _createPc();
      await _attachLocalMedia(video: video);
      final offer = await _pc!.createOffer({
        'offerToReceiveAudio': true,
        'offerToReceiveVideo': video,
      });
      await _pc!.setLocalDescription(offer);
      xmpp.sendCallOffer(
        callId: id,
        to: peerId,
        video: video,
        sdp: offer.sdp ?? '',
      );
    } catch (e) {
      debugPrint('[call] startCall failed: $e');
      await endCall(reason: 'error');
    }
  }

  // -------------------------------------------------------------------
  // Incoming call control
  // -------------------------------------------------------------------
  Future<void> acceptCall() async {
    final c = _active;
    if (c == null || c.direction != CallDirection.incoming) return;
    if (!await _requestPermissions(video: c.video)) {
      await rejectCall(reason: 'no-permission');
      return;
    }
    try {
      await _ensureRenderers();
      await _attachLocalMedia(video: c.video);
      final answer = await _pc!.createAnswer({
        'offerToReceiveAudio': true,
        'offerToReceiveVideo': c.video,
      });
      await _pc!.setLocalDescription(answer);
      xmpp.sendCallAnswer(callId: c.id, to: c.peerId, sdp: answer.sdp ?? '');
      c.state = CallState.connecting;
      notifyListeners();
    } catch (e) {
      debugPrint('[call] accept failed: $e');
      await endCall(reason: 'error');
    }
  }

  Future<void> rejectCall({String reason = 'declined'}) async {
    final c = _active;
    if (c == null) return;
    xmpp.sendCallReject(callId: c.id, to: c.peerId, reason: reason);
    await _teardown(state: CallState.ended, reason: reason);
  }

  Future<void> endCall({String reason = 'hangup'}) async {
    final c = _active;
    if (c == null) return;
    xmpp.sendCallEnd(callId: c.id, to: c.peerId, reason: reason);
    await _teardown(state: CallState.ended, reason: reason);
  }

  // -------------------------------------------------------------------
  // Controls
  // -------------------------------------------------------------------
  void toggleMic() {
    _micMuted = !_micMuted;
    for (final t in _localStream?.getAudioTracks() ?? const []) {
      t.enabled = !_micMuted;
    }
    notifyListeners();
  }

  void toggleCamera() {
    _cameraOff = !_cameraOff;
    for (final t in _localStream?.getVideoTracks() ?? const []) {
      t.enabled = !_cameraOff;
    }
    notifyListeners();
  }

  Future<void> toggleSpeaker() async {
    _speakerOn = !_speakerOn;
    try {
      await Helper.setSpeakerphoneOn(_speakerOn);
    } catch (_) {}
    notifyListeners();
  }

  Future<void> switchCamera() async {
    final track = _localStream?.getVideoTracks().firstOrNull;
    if (track == null) return;
    try {
      await Helper.switchCamera(track);
      _frontCamera = !_frontCamera;
      notifyListeners();
    } catch (_) {}
  }

  // -------------------------------------------------------------------
  // Signaling sink
  // -------------------------------------------------------------------
  Future<void> _onSignal(CallSignal s) async {
    // Ignore stanzas not addressed to us.
    final me = xmpp.myJid;
    if (me == null) return;
    if (s.to != me && s.from != me) return;

    switch (s.kind) {
      case CallSignalKind.offer:
        if (_active != null) {
          // Already busy — auto-reject.
          xmpp.sendCallReject(callId: s.callId, to: s.from, reason: 'busy');
          return;
        }
        _active = ActiveCall(
          id: s.callId,
          peerId: s.from,
          video: s.video,
          direction: CallDirection.incoming,
          state: CallState.ringing,
        );
        await _ensureRenderers();
        await _createPc();
        try {
          await _pc!.setRemoteDescription(
            RTCSessionDescription(s.sdp ?? '', 'offer'),
          );
        } catch (e) {
          debugPrint('[call] setRemoteDescription(offer) failed: $e');
        }
        await _flushPendingIce();
        notifyListeners();
        break;

      case CallSignalKind.answer:
        final c = _active;
        if (c == null) return;
        try {
          await _pc?.setRemoteDescription(
            RTCSessionDescription(s.sdp ?? '', 'answer'),
          );
          c.state = CallState.connecting;
          notifyListeners();
        } catch (e) {
          debugPrint('[call] setRemoteDescription(answer) failed: $e');
        }
        await _flushPendingIce();
        break;

      case CallSignalKind.ice:
        if (s.candidate == null) return;
        final cand = RTCIceCandidate(s.candidate!, s.sdpMid, s.sdpMLineIndex);
        if (_pc == null) {
          _pendingRemoteIce.add(cand);
          return;
        }
        final remoteSet = (await _pc!.getRemoteDescription()) != null;
        if (!remoteSet) {
          _pendingRemoteIce.add(cand);
        } else {
          try {
            await _pc!.addCandidate(cand);
          } catch (e) {
            debugPrint('[call] addCandidate failed: $e');
          }
        }
        break;

      case CallSignalKind.end:
      case CallSignalKind.reject:
      case CallSignalKind.cancel:
        await _teardown(
          state: CallState.ended,
          reason: s.reason ?? s.kind.name,
        );
        break;
    }
  }

  // -------------------------------------------------------------------
  // Wiring
  // -------------------------------------------------------------------
  Future<bool> _requestPermissions({required bool video}) async {
    final perms = <Permission>[Permission.microphone];
    if (video) perms.add(Permission.camera);
    final res = await perms.request();
    return res.values.every((s) => s.isGranted);
  }

  Future<void> _createPc() async {
    final cfg = {
      'iceServers': [
        {'urls': 'stun:stun.l.google.com:19302'},
        {'urls': 'stun:stun1.l.google.com:19302'},
      ],
      'sdpSemantics': 'unified-plan',
    };
    final pc = await createPeerConnection(cfg);
    _pc = pc;

    pc.onIceCandidate = (cand) {
      final c = _active;
      if (c == null) return;
      final s = cand.candidate;
      if (s == null || s.isEmpty) return;
      xmpp.sendCallIce(
        callId: c.id,
        to: c.peerId,
        candidate: s,
        sdpMid: cand.sdpMid,
        sdpMLineIndex: cand.sdpMLineIndex,
      );
    };

    pc.onTrack = (event) {
      if (event.streams.isEmpty) return;
      _remoteStream = event.streams.first;
      remoteRenderer.srcObject = _remoteStream;
      notifyListeners();
    };

    pc.onConnectionState = (state) {
      final c = _active;
      if (c == null) return;
      switch (state) {
        case RTCPeerConnectionState.RTCPeerConnectionStateConnected:
          c.state = CallState.connected;
          c.connectedAt ??= DateTime.now();
          notifyListeners();
          break;
        case RTCPeerConnectionState.RTCPeerConnectionStateFailed:
        case RTCPeerConnectionState.RTCPeerConnectionStateClosed:
        case RTCPeerConnectionState.RTCPeerConnectionStateDisconnected:
          _teardown(state: CallState.ended, reason: 'pc-${state.name}');
          break;
        default:
          break;
      }
    };
  }

  Future<void> _attachLocalMedia({required bool video}) async {
    final constraints = <String, dynamic>{
      'audio': true,
      'video': video
          ? {
              'facingMode': _frontCamera ? 'user' : 'environment',
              'width': {'ideal': 640},
              'height': {'ideal': 480},
              'frameRate': {'ideal': 24},
            }
          : false,
    };
    final stream = await navigator.mediaDevices.getUserMedia(constraints);
    _localStream = stream;
    localRenderer.srcObject = stream;
    for (final track in stream.getTracks()) {
      await _pc?.addTrack(track, stream);
    }
    notifyListeners();
  }

  Future<void> _flushPendingIce() async {
    final pc = _pc;
    if (pc == null) return;
    final remoteSet = (await pc.getRemoteDescription()) != null;
    if (!remoteSet) return;
    final queued = List<RTCIceCandidate>.from(_pendingRemoteIce);
    _pendingRemoteIce.clear();
    for (final c in queued) {
      try {
        await pc.addCandidate(c);
      } catch (e) {
        debugPrint('[call] queued addCandidate failed: $e');
      }
    }
  }

  Future<void> _teardown({
    CallState state = CallState.ended,
    String? reason,
  }) async {
    if (_active != null) {
      _active!.state = state;
      _active!.endReason = reason;
      notifyListeners();
    }
    try {
      await _pc?.close();
    } catch (_) {}
    _pc = null;
    try {
      for (final t in _localStream?.getTracks() ?? const []) {
        await t.stop();
      }
      await _localStream?.dispose();
    } catch (_) {}
    _localStream = null;
    try {
      await _remoteStream?.dispose();
    } catch (_) {}
    _remoteStream = null;
    localRenderer.srcObject = null;
    remoteRenderer.srcObject = null;
    _pendingRemoteIce.clear();
    _micMuted = false;
    _cameraOff = false;
    // Keep _active around briefly so the UI can show "Call ended"; the
    // call screen pops itself and then we clear it.
    Future.delayed(const Duration(milliseconds: 600), () {
      _active = null;
      notifyListeners();
    });
  }
}

extension _FirstOrNull<E> on Iterable<E> {
  E? get firstOrNull => isEmpty ? null : first;
}
