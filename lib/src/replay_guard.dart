import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;

import 'secure_key_vault.dart';

enum PqcReplayDecision { accepted, duplicate, messageIdCollision }

abstract interface class PqcReplayStore {
  /// Atomically stores [payloadDigest] for a new message id and returns the
  /// digest already stored when another caller won the race.
  Future<String?> claim({
    required String accountBinding,
    required int conversationId,
    required String messageId,
    required String payloadDigest,
  });
}

class PqcMemoryReplayStore implements PqcReplayStore {
  final Map<String, String> _claims = {};

  @override
  Future<String?> claim({
    required String accountBinding,
    required int conversationId,
    required String messageId,
    required String payloadDigest,
  }) async {
    final key = '$accountBinding|$conversationId|$messageId';
    final existing = _claims[key];
    if (existing == null) _claims[key] = payloadDigest;
    return existing;
  }
}

/// Durable replay claims backed by the same atomic storage contract as keys.
class PqcAtomicReplayStore implements PqcReplayStore {
  const PqcAtomicReplayStore(this._store);

  static const storageNamespace = 'pqc-engine-sdk.replay.v1';
  final PqcAtomicStore _store;

  @override
  Future<String?> claim({
    required String accountBinding,
    required int conversationId,
    required String messageId,
    required String payloadDigest,
  }) async {
    final opaqueKey = crypto.sha256
        .convert(utf8.encode('$accountBinding|$conversationId|$messageId'))
        .toString();
    final existing = await _store.read(
      namespace: storageNamespace,
      key: opaqueKey,
    );
    if (existing != null) {
      final storedDigest = utf8.decode(existing.bytes);
      if (crypto.sha256.convert(existing.bytes).toString() != existing.sha256) {
        throw const PqcVaultException(
          PqcVaultFailure.corrupted,
          'Replay store checksum is invalid.',
        );
      }
      return storedDigest;
    }
    final bytes = utf8.encode(payloadDigest);
    final saved = await _store.compareAndSet(
      namespace: storageNamespace,
      key: opaqueKey,
      expectedRevision: null,
      value: PqcAtomicRecord(
        revision: 1,
        bytes: bytes,
        sha256: crypto.sha256.convert(bytes).toString(),
      ),
    );
    if (saved) return null;
    final winner = await _store.read(
      namespace: storageNamespace,
      key: opaqueKey,
    );
    if (winner == null) {
      throw const PqcVaultException(
        PqcVaultFailure.unavailable,
        'Replay claim disappeared after a concurrent write.',
      );
    }
    if (crypto.sha256.convert(winner.bytes).toString() != winner.sha256) {
      throw const PqcVaultException(
        PqcVaultFailure.corrupted,
        'Replay store checksum is invalid.',
      );
    }
    return utf8.decode(winner.bytes);
  }
}

class PqcReplayGuard {
  const PqcReplayGuard(this._store);

  final PqcReplayStore _store;

  Future<PqcReplayDecision> claim({
    required String accountBinding,
    required int conversationId,
    required String messageId,
    required String encryptedPayload,
  }) async {
    if (accountBinding.isEmpty || conversationId <= 0 || messageId.isEmpty) {
      throw ArgumentError('Replay identity fields must not be empty.');
    }
    final digest = crypto.sha256
        .convert(utf8.encode(encryptedPayload))
        .toString();
    final existing = await _store.claim(
      accountBinding: accountBinding,
      conversationId: conversationId,
      messageId: messageId,
      payloadDigest: digest,
    );
    if (existing == null) return PqcReplayDecision.accepted;
    return existing == digest
        ? PqcReplayDecision.duplicate
        : PqcReplayDecision.messageIdCollision;
  }
}
