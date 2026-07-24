import 'models.dart';
import 'v2_engine.dart';

enum PqcConversationKind { private, group }

class PqcCompatibilityException implements Exception {
  const PqcCompatibilityException(this.message);

  final String message;

  @override
  String toString() => 'PqcCompatibilityException: $message';
}

/// Registry and production write gate for independently versioned engines.
///
/// A recognized payload is offered to exactly one decoder. A cryptographic
/// failure is never retried as another protocol, preventing downgrade bugs.
class PqcEngineManager {
  PqcEngineManager({
    required Iterable<PqcEngine> decoders,
    String? activeWriterId,
    this.writerEnabled = false,
  }) : _decoders = {for (final engine in decoders) engine.engineId: engine},
       _activeWriterId = activeWriterId {
    if (_decoders.isEmpty) {
      throw ArgumentError('At least one decoder must be registered.');
    }
    if (_decoders.length != decoders.length) {
      throw ArgumentError('Engine ids must be unique.');
    }
    if (activeWriterId != null && !_decoders.containsKey(activeWriterId)) {
      throw ArgumentError('Active writer must be a registered engine.');
    }
  }

  final Map<String, PqcEngine> _decoders;
  final String? _activeWriterId;
  final bool writerEnabled;

  List<PqcEngine> get decoders => List.unmodifiable(_decoders.values);

  PqcEngine? get activeWriter =>
      _activeWriterId == null ? null : _decoders[_activeWriterId];

  PqcEngine resolveDecoder({
    required PqcConversationKind kind,
    required String payload,
  }) {
    final matches = _decoders.values
        .where((engine) {
          return kind == PqcConversationKind.private
              ? engine.recognizesPrivate(payload)
              : engine.recognizesGroup(payload);
        })
        .toList(growable: false);
    if (matches.isEmpty) {
      throw const PqcCompatibilityException('Unsupported payload format.');
    }
    if (matches.length != 1) {
      throw const PqcCompatibilityException(
        'Ambiguous payload format registration.',
      );
    }
    return matches.single;
  }

  PqcEngine requireWriter({
    required PqcConversationKind kind,
    required PqcRemoteCapabilities remote,
  }) {
    final writer = activeWriter;
    if (!writerEnabled || writer == null) {
      throw const PqcCompatibilityException(
        'Encrypted writer is disabled by the production gate.',
      );
    }
    final readable = kind == PqcConversationKind.private
        ? remote.privateReadPrefixes.contains(writer.privatePrefix)
        : remote.groupReadPrefixes.contains(writer.groupPrefix);
    final writable = kind == PqcConversationKind.private
        ? remote.privateWritePrefixes.contains(writer.privatePrefix)
        : remote.groupWritePrefixes.contains(writer.groupPrefix);
    if (!readable || !writable) {
      throw PqcCompatibilityException(
        'Remote endpoint cannot safely read and write ${writer.engineId}.',
      );
    }
    if (writer.protocolVersion < remote.minimumDecoderVersion) {
      throw PqcCompatibilityException(
        'Remote endpoint requires decoder version '
        '${remote.minimumDecoderVersion} or newer.',
      );
    }
    if (!writer.attachmentCipherVersions.every(
      remote.attachmentCipherVersions.contains,
    )) {
      throw const PqcCompatibilityException(
        'Attachment cipher capability mismatch.',
      );
    }
    return writer;
  }
}
