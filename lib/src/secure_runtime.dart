import 'health_monitor.dart';
import 'models.dart';
import 'recovery.dart';
import 'replay_guard.dart';
import 'secure_key_vault.dart';
import 'v2_engine.dart';
import 'version_manager.dart';

class PqcDecryptRetryCoordinator {
  const PqcDecryptRetryCoordinator({
    required this.manager,
    required this.vault,
    required this.recovery,
    required this.healthMonitor,
  });

  final PqcEngineManager manager;
  final PqcKeyVaultRepository vault;
  final PqcRecoveryCoordinator recovery;
  final PqcCryptoHealthMonitor healthMonitor;

  Future<PqcDecodeResult> decryptPrivate({
    required String accountId,
    required PqcConversation conversation,
    required String payload,
    required Map<String, Set<String>> trustedSigningKeysByDevice,
  }) async {
    PqcEngine decoder;
    try {
      decoder = manager.resolveDecoder(
        kind: PqcConversationKind.private,
        payload: payload,
      );
    } on PqcCompatibilityException catch (error) {
      return PqcDecodeError(
        PqcDecodeFailure.unsupported,
        details: error.message,
      );
    }

    Future<PqcDecodeResult> attempt() async {
      final current = await vault.readCurrentDeviceKeyset(accountId);
      final historical = await vault.readHistoricalDeviceKeysets(accountId);
      return decoder.decryptPrivate(
        conversation: conversation,
        payload: payload,
        localKeysets: [?current, ...historical],
        trustedSigningKeysByDevice: trustedSigningKeysByDevice,
      );
    }

    final first = await attempt();
    if (first is! PqcDecodeError ||
        first.failure != PqcDecodeFailure.keyMissing) {
      return first;
    }
    if (!await recovery.restoreLatest(accountId)) return first;
    final retried = await attempt();
    if (retried is PqcDecoded) {
      healthMonitor.resolve(PqcHealthIssue.currentKeyMissing);
    }
    return retried;
  }

  Future<PqcDecodeResult> decryptGroup({
    required String accountId,
    required PqcConversation conversation,
    required String payload,
    Map<String, Set<String>> trustedSigningKeysByDevice = const {},
  }) async {
    PqcEngine decoder;
    try {
      decoder = manager.resolveDecoder(
        kind: PqcConversationKind.group,
        payload: payload,
      );
    } on PqcCompatibilityException catch (error) {
      return PqcDecodeError(
        PqcDecodeFailure.unsupported,
        details: error.message,
      );
    }
    final metadata = decoder.inspectGroup(payload);
    if (metadata == null) {
      return const PqcDecodeError(PqcDecodeFailure.corrupted);
    }

    Future<PqcDecodeResult> attempt() async {
      final epochs = <String, PqcGroupEpoch>{};
      // Frozen V2 group payloads use an epoch id.  V3 group payloads use
      // recipient-device key wraps and intentionally expose an empty epoch id.
      if (metadata.epochId.isNotEmpty) {
        final epoch = await vault.readGroupEpoch(
          accountId: accountId,
          conversationId: conversation.id,
          epochId: metadata.epochId,
        );
        if (epoch != null) epochs[epoch.epochId] = epoch;
      }
      final current = await vault.readCurrentDeviceKeyset(accountId);
      final historical = await vault.readHistoricalDeviceKeysets(accountId);
      return decoder.decryptGroup(
        conversation: conversation,
        payload: payload,
        epochsById: epochs,
        localKeysets: [?current, ...historical],
        trustedSigningKeysByDevice: trustedSigningKeysByDevice,
      );
    }

    final first = await attempt();
    if (first is! PqcDecodeError ||
        first.failure != PqcDecodeFailure.keyMissing) {
      return first;
    }
    if (!await recovery.restoreLatest(accountId)) return first;
    return attempt();
  }
}

/// Host-neutral security orchestration around independently versioned engines.
class PqcSecureRuntime {
  PqcSecureRuntime({
    required this.manager,
    required this.vault,
    required this.recovery,
    required this.replayGuard,
    PqcCryptoHealthMonitor? healthMonitor,
  }) : healthMonitor = healthMonitor ?? recovery.healthMonitor {
    decryptRetry = PqcDecryptRetryCoordinator(
      manager: manager,
      vault: vault,
      recovery: recovery,
      healthMonitor: this.healthMonitor,
    );
  }

  final PqcEngineManager manager;
  final PqcKeyVaultRepository vault;
  final PqcRecoveryCoordinator recovery;
  final PqcReplayGuard replayGuard;
  final PqcCryptoHealthMonitor healthMonitor;
  late final PqcDecryptRetryCoordinator decryptRetry;

  /// Called after authentication and before messages are loaded or written.
  Future<void> initializeAccount(String accountId) async {
    try {
      await vault.verifyIntegrity(accountId);
      healthMonitor.resolve(PqcHealthIssue.storageCorrupted);
      healthMonitor.resolve(PqcHealthIssue.storageUnavailable);
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.corrupted
            ? PqcHealthIssue.storageCorrupted
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      rethrow;
    }

    try {
      await recovery.synchronize(accountId);
    } on PqcRecoveryException catch (error) {
      healthMonitor.report(
        error.failure == PqcRecoveryFailure.revisionConflict ||
                error.failure == PqcRecoveryFailure.corrupted
            ? PqcHealthIssue.recoveryConflict
            : PqcHealthIssue.recoveryUnavailable,
        blocking: true,
      );
      rethrow;
    }
    final current = await vault.readCurrentDeviceKeyset(accountId);
    if (current == null) {
      healthMonitor.report(PqcHealthIssue.currentKeyMissing, blocking: true);
    } else {
      healthMonitor.resolve(PqcHealthIssue.currentKeyMissing);
    }
  }

  /// Atomically stores and backs up a new key before the host may publish it.
  Future<PqcDeviceKeyset> rotateDeviceKeyset({
    required String accountId,
    required String deviceId,
  }) async {
    final engine = manager.activeWriter;
    if (engine == null) {
      throw const PqcCompatibilityException(
        'No active writer is configured for key rotation.',
      );
    }
    final keyset = engine.generateDeviceKeyset(deviceId);
    try {
      await vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: keyset,
        makeCurrent: true,
      );
      await recovery.synchronize(accountId);
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.continuityViolation
            ? PqcHealthIssue.continuityViolation
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      rethrow;
    } on PqcRecoveryException {
      healthMonitor.report(PqcHealthIssue.recoveryUnavailable, blocking: true);
      rethrow;
    }
    healthMonitor.resolve(PqcHealthIssue.currentKeyMissing);
    healthMonitor.resolve(PqcHealthIssue.continuityViolation);
    healthMonitor.resolve(PqcHealthIssue.recoveryUnavailable);
    return keyset;
  }

  /// Retires a revoked device key while preserving historical decryption.
  /// A new writer key must be rotated before another encrypted send.
  Future<void> revokeCurrentDevice({
    required String accountId,
    required String deviceId,
  }) async {
    await vault.revokeCurrentDeviceKeyset(
      accountId: accountId,
      deviceId: deviceId,
    );
    await recovery.synchronize(accountId);
    healthMonitor.report(PqcHealthIssue.currentKeyMissing, blocking: true);
  }

  /// Persists a received group epoch and its recovery snapshot before ACK.
  Future<void> persistGroupEpochBeforeAck({
    required String accountId,
    required int conversationId,
    required PqcGroupEpoch epoch,
  }) async {
    try {
      await vault.saveGroupEpoch(
        accountId: accountId,
        conversationId: conversationId,
        epoch: epoch,
      );
      await recovery.synchronize(accountId);
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.continuityViolation
            ? PqcHealthIssue.continuityViolation
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      rethrow;
    } on PqcRecoveryException {
      healthMonitor.report(PqcHealthIssue.recoveryUnavailable, blocking: true);
      rethrow;
    }
  }

  PqcEngine requireWriter({
    required PqcConversationKind kind,
    required PqcRemoteCapabilities remote,
  }) {
    healthMonitor.assertSafeToWrite();
    return manager.requireWriter(kind: kind, remote: remote);
  }

  /// Integrity check used directly in the send path before encryption.
  Future<PqcEngine> prepareWriter({
    required String accountId,
    required PqcConversationKind kind,
    required PqcRemoteCapabilities remote,
  }) async {
    try {
      await vault.verifyIntegrity(accountId);
      final current = await vault.readCurrentDeviceKeyset(accountId);
      if (current == null) {
        healthMonitor.report(PqcHealthIssue.currentKeyMissing, blocking: true);
      } else {
        healthMonitor.resolve(PqcHealthIssue.currentKeyMissing);
      }
    } on PqcVaultException catch (error) {
      healthMonitor.report(
        error.failure == PqcVaultFailure.corrupted
            ? PqcHealthIssue.storageCorrupted
            : PqcHealthIssue.storageUnavailable,
        blocking: true,
      );
      rethrow;
    }
    return requireWriter(kind: kind, remote: remote);
  }

  Future<PqcReplayDecision> acceptInbound({
    required String accountId,
    required int conversationId,
    required String messageId,
    required String encryptedPayload,
  }) async {
    final decision = await replayGuard.claim(
      accountBinding: pqcAccountBinding(accountId),
      conversationId: conversationId,
      messageId: messageId,
      encryptedPayload: encryptedPayload,
    );
    if (decision != PqcReplayDecision.accepted) {
      healthMonitor.report(
        PqcHealthIssue.replayDetected,
        blocking: decision == PqcReplayDecision.messageIdCollision,
        correlationId: messageId,
      );
    }
    return decision;
  }
}
