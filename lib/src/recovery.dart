import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'health_monitor.dart';
import 'key_repository.dart';
import 'primitives.dart';
import 'secure_key_vault.dart';

enum PqcRecoveryFailure {
  unavailable,
  corrupted,
  wrongAccount,
  invalidKey,
  revisionConflict,
}

class PqcRecoveryException implements Exception {
  const PqcRecoveryException(this.failure, this.message);

  final PqcRecoveryFailure failure;
  final String message;

  @override
  String toString() => 'PqcRecoveryException($failure): $message';
}

abstract interface class PqcRecoveryKeyProvider {
  /// Returns an account-bound 32-byte recovery master key.
  ///
  /// The host may unwrap it with Keychain/Keystore, an enterprise HSM or an
  /// authenticated account-recovery flow. It must never be sent to the
  /// recovery transport.
  Future<List<int>> recoveryKey(String accountId);
}

/// Optional stronger recovery transport used for race-free revision updates.
abstract interface class PqcConditionalRecoveryRepository
    implements PqcRecoveryRepository {
  Future<bool> uploadIfCurrentRevision({
    required String accountId,
    required int? expectedCurrentRevision,
    required int revision,
    required List<int> encryptedBlob,
    required String sha256,
  });
}

class PqcMemoryRecoveryRepository implements PqcConditionalRecoveryRepository {
  final Map<String, PqcRecoverySnapshot> _snapshots = {};

  @override
  Future<PqcRecoverySnapshot?> downloadLatestEncryptedSnapshot(
    String accountId,
  ) async {
    final value = _snapshots[accountId];
    return value == null
        ? null
        : PqcRecoverySnapshot(
            revision: value.revision,
            encryptedBlob: value.encryptedBlob,
            sha256: value.sha256,
          );
  }

  @override
  Future<void> uploadEncryptedSnapshot({
    required String accountId,
    required int revision,
    required List<int> encryptedBlob,
    required String sha256,
  }) async {
    final existing = _snapshots[accountId];
    if (existing != null && revision <= existing.revision) {
      throw const PqcRecoveryException(
        PqcRecoveryFailure.revisionConflict,
        'Recovery revision must increase monotonically.',
      );
    }
    _snapshots[accountId] = PqcRecoverySnapshot(
      revision: revision,
      encryptedBlob: encryptedBlob,
      sha256: sha256,
    );
  }

  @override
  Future<bool> uploadIfCurrentRevision({
    required String accountId,
    required int? expectedCurrentRevision,
    required int revision,
    required List<int> encryptedBlob,
    required String sha256,
  }) async {
    final existing = _snapshots[accountId];
    if (existing?.revision != expectedCurrentRevision ||
        (existing != null && revision <= existing.revision)) {
      return false;
    }
    _snapshots[accountId] = PqcRecoverySnapshot(
      revision: revision,
      encryptedBlob: encryptedBlob,
      sha256: sha256,
    );
    return true;
  }

  void tamperForTest(String accountId) {
    final current = _snapshots[accountId];
    if (current == null || current.encryptedBlob.isEmpty) return;
    final bytes = [...current.encryptedBlob]..last ^= 0x01;
    _snapshots[accountId] = PqcRecoverySnapshot(
      revision: current.revision,
      encryptedBlob: bytes,
      sha256: current.sha256,
    );
  }
}

class PqcRecoveryEnvelopeCodec {
  PqcRecoveryEnvelopeCodec({PqcPrimitiveSuite? primitives})
    : _primitives = primitives ?? DartPqcPrimitiveSuite();

  static const schemaVersion = 1;
  final PqcPrimitiveSuite _primitives;

  Future<Uint8List> encrypt({
    required String accountId,
    required PqcKeyVaultSnapshot snapshot,
    required List<int> recoveryKey,
  }) async {
    _validateKey(recoveryKey);
    if (snapshot.accountBinding != pqcAccountBinding(accountId)) {
      throw const PqcRecoveryException(
        PqcRecoveryFailure.wrongAccount,
        'Cannot encrypt another account’s key vault.',
      );
    }
    final aad = _associatedData(
      accountBinding: snapshot.accountBinding,
      revision: snapshot.revision,
    );
    final box = await _primitives.encryptAead(
      plaintext: utf8.encode(jsonEncode(snapshot.toJson())),
      key: recoveryKey,
      nonce: _primitives.randomBytes(12),
      associatedData: aad,
    );
    return Uint8List.fromList(
      utf8.encode(
        jsonEncode({
          'schema_version': schemaVersion,
          'account_binding': snapshot.accountBinding,
          'revision': snapshot.revision,
          'nonce': base64Encode(box.nonce),
          'ciphertext': base64Encode(box.ciphertext),
          'mac': base64Encode(box.mac),
        }),
      ),
    );
  }

  Future<PqcKeyVaultSnapshot> decrypt({
    required String accountId,
    required List<int> encryptedBlob,
    required List<int> recoveryKey,
  }) async {
    _validateKey(recoveryKey);
    try {
      final decoded = jsonDecode(utf8.decode(encryptedBlob));
      if (decoded is! Map) throw const FormatException();
      final document = Map<String, dynamic>.from(decoded);
      final accountBinding = document['account_binding'] as String? ?? '';
      final revision = document['revision'] as int? ?? -1;
      if (document['schema_version'] != schemaVersion || revision < 1) {
        throw const FormatException();
      }
      if (!_constantTimeEquals(accountBinding, pqcAccountBinding(accountId))) {
        throw const PqcRecoveryException(
          PqcRecoveryFailure.wrongAccount,
          'Recovery envelope belongs to another account.',
        );
      }
      final clear = await _primitives.decryptAead(
        box: PqcAeadBox(
          nonce: base64Decode(document['nonce'] as String? ?? ''),
          ciphertext: base64Decode(document['ciphertext'] as String? ?? ''),
          mac: base64Decode(document['mac'] as String? ?? ''),
        ),
        key: recoveryKey,
        associatedData: _associatedData(
          accountBinding: accountBinding,
          revision: revision,
        ),
      );
      final snapshotJson = jsonDecode(utf8.decode(clear));
      if (snapshotJson is! Map) throw const FormatException();
      final snapshot = PqcKeyVaultSnapshot.fromJson(
        Map<String, dynamic>.from(snapshotJson),
      );
      if (snapshot.revision != revision ||
          snapshot.accountBinding != accountBinding) {
        throw const FormatException();
      }
      return snapshot;
    } on PqcRecoveryException {
      rethrow;
    } catch (_) {
      throw const PqcRecoveryException(
        PqcRecoveryFailure.corrupted,
        'Recovery envelope authentication or structure is invalid.',
      );
    }
  }

  List<int> _associatedData({
    required String accountBinding,
    required int revision,
  }) => utf8.encode('pqc-recovery-envelope-v1|$accountBinding|$revision');

  void _validateKey(List<int> key) {
    if (key.length != 32) {
      throw const PqcRecoveryException(
        PqcRecoveryFailure.invalidKey,
        'Recovery master key must contain exactly 32 bytes.',
      );
    }
  }
}

class PqcRecoveryCoordinator {
  PqcRecoveryCoordinator({
    required this.vault,
    required this.transport,
    required this.keyProvider,
    PqcRecoveryEnvelopeCodec? codec,
    PqcCryptoHealthMonitor? healthMonitor,
  }) : codec = codec ?? PqcRecoveryEnvelopeCodec(),
       healthMonitor = healthMonitor ?? PqcCryptoHealthMonitor();

  final PqcKeyVaultRepository vault;
  final PqcRecoveryRepository transport;
  final PqcRecoveryKeyProvider keyProvider;
  final PqcRecoveryEnvelopeCodec codec;
  final PqcCryptoHealthMonitor healthMonitor;

  Future<bool> restoreLatest(String accountId) async {
    final remote = await transport.downloadLatestEncryptedSnapshot(accountId);
    if (remote == null) {
      healthMonitor.report(PqcHealthIssue.recoveryUnavailable, blocking: false);
      return false;
    }
    _verifyTransportHash(remote);
    final key = await keyProvider.recoveryKey(accountId);
    final snapshot = await codec.decrypt(
      accountId: accountId,
      encryptedBlob: remote.encryptedBlob,
      recoveryKey: key,
    );
    if (snapshot.revision != remote.revision) {
      throw const PqcRecoveryException(
        PqcRecoveryFailure.corrupted,
        'Transport and encrypted recovery revisions disagree.',
      );
    }
    await vault.mergeSnapshot(accountId: accountId, snapshot: snapshot);
    healthMonitor.resolve(PqcHealthIssue.recoveryUnavailable);
    healthMonitor.resolve(PqcHealthIssue.currentKeyMissing);
    return true;
  }

  /// Reconciles local and remote revisions without allowing a downgrade.
  Future<void> synchronize(String accountId) async {
    final local = await vault.exportSnapshot(accountId);
    final remote = await transport.downloadLatestEncryptedSnapshot(accountId);
    if (!local.hasAnyKeyMaterial) {
      if (remote == null) {
        healthMonitor.report(PqcHealthIssue.currentKeyMissing, blocking: true);
        return;
      }
      await restoreLatest(accountId);
      return;
    }

    if (remote == null) {
      await _upload(accountId, local, expectedRemoteRevision: null);
      return;
    }
    _verifyTransportHash(remote);
    if (remote.revision > local.revision) {
      await restoreLatest(accountId);
      return;
    }
    if (remote.revision < local.revision) {
      await _upload(accountId, local, expectedRemoteRevision: remote.revision);
      return;
    }

    final remoteSnapshot = await codec.decrypt(
      accountId: accountId,
      encryptedBlob: remote.encryptedBlob,
      recoveryKey: await keyProvider.recoveryKey(accountId),
    );
    if (!_sameSnapshotMaterial(local, remoteSnapshot)) {
      healthMonitor.report(PqcHealthIssue.recoveryConflict, blocking: true);
      throw const PqcRecoveryException(
        PqcRecoveryFailure.revisionConflict,
        'Equal recovery revisions contain different key material.',
      );
    }
    healthMonitor.resolve(PqcHealthIssue.recoveryConflict);
    healthMonitor.resolve(PqcHealthIssue.recoveryUnavailable);
  }

  Future<void> _upload(
    String accountId,
    PqcKeyVaultSnapshot local, {
    required int? expectedRemoteRevision,
  }) async {
    if (local.revision < 1) {
      throw const PqcRecoveryException(
        PqcRecoveryFailure.revisionConflict,
        'An empty recovery revision cannot be uploaded.',
      );
    }
    final blob = await codec.encrypt(
      accountId: accountId,
      snapshot: local,
      recoveryKey: await keyProvider.recoveryKey(accountId),
    );
    final sha256 = _sha256Hex(blob);
    if (transport case final PqcConditionalRecoveryRepository conditional) {
      final saved = await conditional.uploadIfCurrentRevision(
        accountId: accountId,
        expectedCurrentRevision: expectedRemoteRevision,
        revision: local.revision,
        encryptedBlob: blob,
        sha256: sha256,
      );
      if (!saved) {
        healthMonitor.report(PqcHealthIssue.recoveryConflict, blocking: true);
        throw const PqcRecoveryException(
          PqcRecoveryFailure.revisionConflict,
          'Recovery changed concurrently; refusing to overwrite it.',
        );
      }
    } else {
      throw const PqcRecoveryException(
        PqcRecoveryFailure.unavailable,
        'Production recovery writes require conditional revision support.',
      );
    }
    healthMonitor.resolve(PqcHealthIssue.recoveryConflict);
    healthMonitor.resolve(PqcHealthIssue.recoveryUnavailable);
  }

  void _verifyTransportHash(PqcRecoverySnapshot snapshot) {
    if (!_constantTimeEquals(
      _sha256Hex(snapshot.encryptedBlob),
      snapshot.sha256,
    )) {
      healthMonitor.report(PqcHealthIssue.recoveryConflict, blocking: true);
      throw const PqcRecoveryException(
        PqcRecoveryFailure.corrupted,
        'Encrypted recovery transport checksum is invalid.',
      );
    }
  }
}

bool _sameSnapshotMaterial(
  PqcKeyVaultSnapshot left,
  PqcKeyVaultSnapshot right,
) {
  final leftJson = {...left.toJson()}..remove('revision');
  final rightJson = {...right.toJson()}..remove('revision');
  return jsonEncode(leftJson) == jsonEncode(rightJson);
}

String _sha256Hex(List<int> bytes) => crypto.sha256.convert(bytes).toString();

bool _constantTimeEquals(String left, String right) {
  final leftBytes = utf8.encode(left);
  final rightBytes = utf8.encode(right);
  if (leftBytes.length != rightBytes.length) return false;
  var difference = 0;
  for (var index = 0; index < leftBytes.length; index++) {
    difference |= leftBytes[index] ^ rightBytes[index];
  }
  return difference == 0;
}
