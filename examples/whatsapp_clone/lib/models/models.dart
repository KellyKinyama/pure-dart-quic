// Data models for the WhatsApp-style client.

class Contact {
  final String jid;
  String name;
  String? avatar;
  bool online;
  DateTime lastSeen;

  Contact({
    required this.jid,
    required this.name,
    this.avatar,
    this.online = false,
    DateTime? lastSeen,
  }) : lastSeen = lastSeen ?? DateTime.now();
}

class ChatMessage {
  final String id;
  final String from;
  final String to; // peer jid or group id
  final String body;
  final DateTime ts;
  final bool fromMe;
  MessageStatus status;
  final bool isGroup;

  ChatMessage({
    required this.id,
    required this.from,
    required this.to,
    required this.body,
    required this.ts,
    required this.fromMe,
    this.status = MessageStatus.sent,
    this.isGroup = false,
  });
}

enum MessageStatus { sending, sent, delivered, read, failed }

class ChatThread {
  final String peerId; // jid or group id
  final bool isGroup;
  String displayName;
  String? avatar;
  final List<ChatMessage> messages = <ChatMessage>[];
  int unread = 0;
  String? typingPeer;
  DateTime updatedAt;

  ChatThread({
    required this.peerId,
    required this.displayName,
    this.avatar,
    this.isGroup = false,
    DateTime? updatedAt,
  }) : updatedAt = updatedAt ?? DateTime.now();

  ChatMessage? get lastMessage => messages.isEmpty ? null : messages.last;
}

class Group {
  final String id;
  String name;
  final Set<String> members;
  Group({required this.id, required this.name, required this.members});
}
