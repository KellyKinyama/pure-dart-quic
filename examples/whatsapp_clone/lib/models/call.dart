// Call signaling types used by XmppService and CallService.

enum CallSignalKind { offer, answer, ice, end, reject, cancel }

class CallSignal {
  final CallSignalKind kind;
  final String callId;
  final String from;
  final String to;
  final bool video;
  final String? sdp; // for offer/answer (base64 of SDP text)
  final String? candidate; // for ice (base64 of candidate text)
  final String? sdpMid;
  final int? sdpMLineIndex;
  final String? reason;

  CallSignal({
    required this.kind,
    required this.callId,
    required this.from,
    required this.to,
    this.video = false,
    this.sdp,
    this.candidate,
    this.sdpMid,
    this.sdpMLineIndex,
    this.reason,
  });
}

enum CallState { idle, ringing, dialing, connecting, connected, ended }

enum CallDirection { outgoing, incoming }
