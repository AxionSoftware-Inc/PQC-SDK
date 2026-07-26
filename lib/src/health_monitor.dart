import 'dart:async';

enum PqcHealthIssue {
  storageCorrupted,
  storageUnavailable,
  currentKeyMissing,
  continuityViolation,
  recoveryUnavailable,
  recoveryConflict,
  replayDetected,
}

class PqcHealthEvent {
  const PqcHealthEvent({
    required this.issue,
    required this.isBlocking,
    required this.correlationId,
  });

  final PqcHealthIssue issue;
  final bool isBlocking;
  final String correlationId;
}

class PqcHealthSnapshot {
  const PqcHealthSnapshot({
    required this.blockingIssues,
    required this.advisoryIssues,
  });

  final Set<PqcHealthIssue> blockingIssues;
  final Set<PqcHealthIssue> advisoryIssues;

  bool get isSafeToWrite => blockingIssues.isEmpty;
  bool get isHealthy => blockingIssues.isEmpty && advisoryIssues.isEmpty;
}

class PqcCryptoHealthException implements Exception {
  const PqcCryptoHealthException(this.issues);

  final Set<PqcHealthIssue> issues;

  @override
  String toString() =>
      'PqcCryptoHealthException: encrypted writes blocked by $issues';
}

/// Secret-free health state used to fail closed before an encrypted write.
class PqcCryptoHealthMonitor {
  final Set<PqcHealthIssue> _blocking = {};
  final Set<PqcHealthIssue> _advisory = {};
  final StreamController<PqcHealthEvent> _events =
      StreamController<PqcHealthEvent>.broadcast(sync: true);

  Stream<PqcHealthEvent> get events => _events.stream;

  PqcHealthSnapshot get snapshot => PqcHealthSnapshot(
    blockingIssues: Set.unmodifiable(_blocking),
    advisoryIssues: Set.unmodifiable(_advisory),
  );

  void report(
    PqcHealthIssue issue, {
    required bool blocking,
    String correlationId = '',
  }) {
    (blocking ? _blocking : _advisory).add(issue);
    if (blocking) _advisory.remove(issue);
    _events.add(
      PqcHealthEvent(
        issue: issue,
        isBlocking: blocking,
        correlationId: correlationId,
      ),
    );
  }

  void resolve(PqcHealthIssue issue) {
    _blocking.remove(issue);
    _advisory.remove(issue);
  }

  void assertSafeToWrite() {
    if (_blocking.isNotEmpty) {
      throw PqcCryptoHealthException(Set.unmodifiable(_blocking));
    }
  }

  Future<void> close() => _events.close();
}
