import 'dart:typed_data';

import 'models.dart';

/// Persistence boundary implemented by the host application.
///
/// The SDK deliberately does not depend on Keychain, Keystore, IndexedDB,
/// HTTP or a database. Implementations must encrypt at rest and make
/// [saveDeviceKeyset] and [saveGroupEpoch] atomic before acknowledging them.
abstract interface class PqcKeyRepository {
  Future<PqcDeviceKeyset?> readCurrentDeviceKeyset(String accountId);

  Future<List<PqcDeviceKeyset>> readHistoricalDeviceKeysets(String accountId);

  Future<void> saveDeviceKeyset({
    required String accountId,
    required PqcDeviceKeyset keyset,
    required bool makeCurrent,
  });

  Future<PqcGroupEpoch?> readGroupEpoch({
    required String accountId,
    required int conversationId,
    required String epochId,
  });

  Future<void> saveGroupEpoch({
    required String accountId,
    required int conversationId,
    required PqcGroupEpoch epoch,
  });
}

/// Optional recovery transport boundary.
///
/// Implementations may use an application server, enterprise vault or an
/// offline backup. Blobs must already be encrypted and authenticated before
/// crossing this boundary.
abstract interface class PqcRecoveryRepository {
  Future<void> uploadEncryptedSnapshot({
    required String accountId,
    required int revision,
    required List<int> encryptedBlob,
    required String sha256,
  });

  Future<PqcRecoverySnapshot?> downloadLatestEncryptedSnapshot(
    String accountId,
  );
}

class PqcRecoverySnapshot {
  PqcRecoverySnapshot({
    required this.revision,
    required List<int> encryptedBlob,
    required this.sha256,
  }) : encryptedBlob = Uint8List.fromList(encryptedBlob);

  final int revision;
  final Uint8List encryptedBlob;
  final String sha256;
}
