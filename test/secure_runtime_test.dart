import 'dart:convert';

import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';
import 'package:test/test.dart';

class _FixedRecoveryKeyProvider implements PqcRecoveryKeyProvider {
  const _FixedRecoveryKeyProvider(this.seed);

  final int seed;

  @override
  Future<List<int>> recoveryKey(String accountId) async =>
      List<int>.generate(32, (index) => (seed + index) & 0xff);
}

class _InterruptingAtomicStore implements PqcAtomicStore {
  _InterruptingAtomicStore(this.delegate);

  final PqcMemoryAtomicStore delegate;
  bool interruptNextWrite = false;

  @override
  Future<PqcAtomicRecord?> read({
    required String namespace,
    required String key,
  }) => delegate.read(namespace: namespace, key: key);

  @override
  Future<bool> compareAndSet({
    required String namespace,
    required String key,
    required int? expectedRevision,
    required PqcAtomicRecord value,
  }) async {
    if (interruptNextWrite) {
      interruptNextWrite = false;
      throw StateError('simulated power loss before atomic commit');
    }
    return delegate.compareAndSet(
      namespace: namespace,
      key: key,
      expectedRevision: expectedRevision,
      value: value,
    );
  }
}

class _ConflictingRecoveryTransport
    implements PqcConditionalRecoveryRepository {
  @override
  Future<PqcRecoverySnapshot?> downloadLatestEncryptedSnapshot(
    String accountId,
  ) async => null;

  @override
  Future<void> uploadEncryptedSnapshot({
    required String accountId,
    required int revision,
    required List<int> encryptedBlob,
    required String sha256,
  }) async {}

  @override
  Future<bool> uploadIfCurrentRevision({
    required String accountId,
    required int? expectedCurrentRevision,
    required int revision,
    required List<int> encryptedBlob,
    required String sha256,
  }) async => false;
}

void main() {
  const accountId = 'account-1';
  const privateConversation = PqcConversation(id: 7, type: 'private');
  const groupConversation = PqcConversation(id: 8, type: 'group');
  const capabilities = PqcRemoteCapabilities(
    privateReadPrefixes: {PqcV2Wire.privatePrefix},
    groupReadPrefixes: {PqcV2Wire.groupPrefix},
    privateWritePrefixes: {PqcV2Wire.privatePrefix},
    groupWritePrefixes: {PqcV2Wire.groupPrefix},
    attachmentCipherVersions: {PqcV2Wire.attachmentCipherVersion},
    minimumDecoderVersion: 2,
  );

  late PqcV2Engine engine;

  setUp(() {
    engine = PqcV2Engine();
  });

  test('V2.5 release uses frozen V2 wire and retains its decoder', () {
    final manager = PqcEngineManager(
      decoders: [engine],
      activeWriterId: engine.engineId,
      writerEnabled: true,
      releaseProfile: PqcReleaseProfiles.v25,
    );

    expect(manager.releaseId, '2.5.0');
    expect(manager.activeWriter?.protocolVersion, 2);
    expect(
      manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: capabilities,
      ),
      same(engine),
    );
  });

  test(
    'atomic rotation preserves every old keyset as read-only history',
    () async {
      final vault = PqcIntegrityKeyVault(store: PqcMemoryAtomicStore());
      final first = engine.generateDeviceKeyset('phone');
      final second = engine.generateDeviceKeyset('phone');
      final third = engine.generateDeviceKeyset('phone');

      await vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: first,
        makeCurrent: true,
      );
      await Future.wait([
        vault.saveDeviceKeyset(
          accountId: accountId,
          keyset: second,
          makeCurrent: true,
        ),
        vault.saveDeviceKeyset(
          accountId: accountId,
          keyset: third,
          makeCurrent: true,
        ),
      ]);

      final current = await vault.readCurrentDeviceKeyset(accountId);
      final history = await vault.readHistoricalDeviceKeysets(accountId);
      expect(
        {current!.keysetId, ...history.map((item) => item.keysetId)},
        {first.keysetId, second.keysetId, third.keysetId},
      );
      expect(history, hasLength(2));
    },
  );

  test(
    'power loss before atomic commit leaves the previous vault valid',
    () async {
      final memory = PqcMemoryAtomicStore();
      final store = _InterruptingAtomicStore(memory);
      final vault = PqcIntegrityKeyVault(store: store);
      final first = engine.generateDeviceKeyset('phone');
      final second = engine.generateDeviceKeyset('phone');
      await vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: first,
        makeCurrent: true,
      );

      store.interruptNextWrite = true;
      await expectLater(
        vault.saveDeviceKeyset(
          accountId: accountId,
          keyset: second,
          makeCurrent: true,
        ),
        throwsStateError,
      );

      expect(
        (await vault.readCurrentDeviceKeyset(accountId))?.keysetId,
        first.keysetId,
      );
      await vault.verifyIntegrity(accountId);
    },
  );

  test('chaos writes expose either the old or fully committed vault', () async {
    final memory = PqcMemoryAtomicStore();
    final store = _InterruptingAtomicStore(memory);
    final vault = PqcIntegrityKeyVault(store: store);
    final candidates = List.generate(
      4,
      (index) => engine.generateDeviceKeyset('chaos-phone-$index'),
    );
    final committed = <String>{};

    for (var iteration = 0; iteration < 24; iteration++) {
      final candidate = candidates[iteration % candidates.length];
      store.interruptNextWrite = iteration % 3 == 1;
      try {
        await vault.saveDeviceKeyset(
          accountId: accountId,
          keyset: candidate,
          makeCurrent: true,
        );
        committed.add(candidate.keysetId);
      } on StateError {
        // Simulated crash happened before the atomic commit.
      }
      await vault.verifyIntegrity(accountId);
      final snapshot = await vault.exportSnapshot(accountId);
      final persisted = {
        if (snapshot.currentDeviceKeyset case final current?) current.keysetId,
        ...snapshot.historicalDeviceKeysets.map((item) => item.keysetId),
      };
      expect(persisted, committed);
    }
  });

  test('checksum corruption and keyset rebinding fail closed', () async {
    final memory = PqcMemoryAtomicStore();
    final vault = PqcIntegrityKeyVault(store: memory);
    final keyset = engine.generateDeviceKeyset('phone');
    await vault.saveDeviceKeyset(
      accountId: accountId,
      keyset: keyset,
      makeCurrent: true,
    );
    final conflicting = PqcDeviceKeyset(
      deviceId: keyset.deviceId,
      kemPublicKeyBase64: keyset.kemPublicKeyBase64,
      kemSecretKeyBase64: base64Encode(List<int>.filled(2400, 9)),
      signingPublicKeyBase64: keyset.signingPublicKeyBase64,
      signingSecretKeyBase64: keyset.signingSecretKeyBase64,
    );
    await expectLater(
      vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: conflicting,
        makeCurrent: true,
      ),
      throwsA(
        isA<PqcVaultException>().having(
          (error) => error.failure,
          'failure',
          PqcVaultFailure.continuityViolation,
        ),
      ),
    );

    memory.corruptForTest(
      namespace: PqcIntegrityKeyVault.storageNamespace,
      key: pqcAccountBinding(accountId),
    );
    await expectLater(
      vault.verifyIntegrity(accountId),
      throwsA(
        isA<PqcVaultException>().having(
          (error) => error.failure,
          'failure',
          PqcVaultFailure.corrupted,
        ),
      ),
    );
  });

  test(
    'encrypted recovery restores reinstall and retries private decrypt',
    () async {
      final transport = PqcMemoryRecoveryRepository();
      const keyProvider = _FixedRecoveryKeyProvider(17);
      final sourceVault = PqcIntegrityKeyVault(store: PqcMemoryAtomicStore());
      final sourceRecovery = PqcRecoveryCoordinator(
        vault: sourceVault,
        transport: transport,
        keyProvider: keyProvider,
      );
      final recipient = engine.generateDeviceKeyset('recipient-phone');
      final sender = engine.generateDeviceKeyset('sender-phone');
      await sourceVault.saveDeviceKeyset(
        accountId: accountId,
        keyset: recipient,
        makeCurrent: true,
      );
      await sourceRecovery.synchronize(accountId);
      final payload = await engine.private.encrypt(
        conversation: privateConversation,
        plaintext: 'reinstall survived',
        sender: sender,
        recipientDevices: [recipient.publicKey],
      );

      final reinstalledVault = PqcIntegrityKeyVault(
        store: PqcMemoryAtomicStore(),
      );
      final health = PqcCryptoHealthMonitor();
      final reinstalledRecovery = PqcRecoveryCoordinator(
        vault: reinstalledVault,
        transport: transport,
        keyProvider: keyProvider,
        healthMonitor: health,
      );
      final retry = PqcDecryptRetryCoordinator(
        manager: PqcEngineManager(decoders: [engine]),
        vault: reinstalledVault,
        recovery: reinstalledRecovery,
        healthMonitor: health,
      );
      final result = await retry.decryptPrivate(
        accountId: accountId,
        conversation: privateConversation,
        payload: payload,
        trustedSigningKeysByDevice: {
          sender.deviceId: {sender.signingPublicKeyBase64},
        },
      );

      expect(result, isA<PqcDecoded>());
      expect((result as PqcDecoded).plaintext, 'reinstall survived');
      expect(
        (await reinstalledVault.readCurrentDeviceKeyset(accountId))?.keysetId,
        recipient.keysetId,
      );
    },
  );

  test(
    'account scopes never leak keys across relogin or account switch',
    () async {
      final vault = PqcIntegrityKeyVault(store: PqcMemoryAtomicStore());
      final first = engine.generateDeviceKeyset('phone');
      final rotated = engine.generateDeviceKeyset('phone');
      await vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: first,
        makeCurrent: true,
      );
      await vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: rotated,
        makeCurrent: true,
      );

      expect(
        (await vault.readCurrentDeviceKeyset(accountId))?.keysetId,
        rotated.keysetId,
      );
      expect(
        (await vault.readHistoricalDeviceKeysets(
          accountId,
        )).map((item) => item.keysetId),
        contains(first.keysetId),
      );
      expect(await vault.readCurrentDeviceKeyset('another-account'), isNull);
      expect(
        await vault.readHistoricalDeviceKeysets('another-account'),
        isEmpty,
      );
      expect(
        (await vault.readCurrentDeviceKeyset(accountId))?.keysetId,
        rotated.keysetId,
      );
    },
  );

  test('encrypted recovery restores group epoch before retry', () async {
    final transport = PqcMemoryRecoveryRepository();
    const keyProvider = _FixedRecoveryKeyProvider(21);
    final sourceVault = PqcIntegrityKeyVault(store: PqcMemoryAtomicStore());
    final sourceRecovery = PqcRecoveryCoordinator(
      vault: sourceVault,
      transport: transport,
      keyProvider: keyProvider,
    );
    final device = engine.generateDeviceKeyset('phone');
    final epoch = PqcGroupEpoch(
      epochId: 'epoch-7',
      secretKeyBytes: List<int>.generate(32, (index) => index),
    );
    await sourceVault.saveDeviceKeyset(
      accountId: accountId,
      keyset: device,
      makeCurrent: true,
    );
    await sourceVault.saveGroupEpoch(
      accountId: accountId,
      conversationId: groupConversation.id,
      epoch: epoch,
    );
    await sourceRecovery.synchronize(accountId);
    final payload = await engine.group.encrypt(
      conversation: groupConversation,
      plaintext: 'group history',
      epoch: epoch,
    );

    final targetVault = PqcIntegrityKeyVault(store: PqcMemoryAtomicStore());
    final targetRecovery = PqcRecoveryCoordinator(
      vault: targetVault,
      transport: transport,
      keyProvider: keyProvider,
    );
    final retry = PqcDecryptRetryCoordinator(
      manager: PqcEngineManager(decoders: [engine]),
      vault: targetVault,
      recovery: targetRecovery,
      healthMonitor: targetRecovery.healthMonitor,
    );
    final result = await retry.decryptGroup(
      accountId: accountId,
      conversation: groupConversation,
      payload: payload,
    );

    expect((result as PqcDecoded).plaintext, 'group history');
  });

  test(
    'recovery rejects tamper, wrong account and concurrent overwrite',
    () async {
      final transport = PqcMemoryRecoveryRepository();
      const keyProvider = _FixedRecoveryKeyProvider(31);
      final vault = PqcIntegrityKeyVault(store: PqcMemoryAtomicStore());
      final recovery = PqcRecoveryCoordinator(
        vault: vault,
        transport: transport,
        keyProvider: keyProvider,
      );
      await vault.saveDeviceKeyset(
        accountId: accountId,
        keyset: engine.generateDeviceKeyset('phone'),
        makeCurrent: true,
      );
      await recovery.synchronize(accountId);
      final remote = await transport.downloadLatestEncryptedSnapshot(accountId);
      await expectLater(
        recovery.codec.decrypt(
          accountId: 'other-account',
          encryptedBlob: remote!.encryptedBlob,
          recoveryKey: await keyProvider.recoveryKey('other-account'),
        ),
        throwsA(
          isA<PqcRecoveryException>().having(
            (error) => error.failure,
            'failure',
            PqcRecoveryFailure.wrongAccount,
          ),
        ),
      );

      transport.tamperForTest(accountId);
      await expectLater(
        recovery.restoreLatest(accountId),
        throwsA(isA<PqcRecoveryException>()),
      );

      final conflictVault = PqcIntegrityKeyVault(store: PqcMemoryAtomicStore());
      await conflictVault.saveDeviceKeyset(
        accountId: accountId,
        keyset: engine.generateDeviceKeyset('second-phone'),
        makeCurrent: true,
      );
      final conflictRecovery = PqcRecoveryCoordinator(
        vault: conflictVault,
        transport: _ConflictingRecoveryTransport(),
        keyProvider: keyProvider,
      );
      await expectLater(
        conflictRecovery.synchronize(accountId),
        throwsA(
          isA<PqcRecoveryException>().having(
            (error) => error.failure,
            'failure',
            PqcRecoveryFailure.revisionConflict,
          ),
        ),
      );
    },
  );

  test('recovery rejects a wrong master key and equal-revision fork', () async {
    final transport = PqcMemoryRecoveryRepository();
    const keyProvider = _FixedRecoveryKeyProvider(51);
    final firstVault = PqcIntegrityKeyVault(store: PqcMemoryAtomicStore());
    final firstRecovery = PqcRecoveryCoordinator(
      vault: firstVault,
      transport: transport,
      keyProvider: keyProvider,
    );
    await firstVault.saveDeviceKeyset(
      accountId: accountId,
      keyset: engine.generateDeviceKeyset('first-phone'),
      makeCurrent: true,
    );
    await firstRecovery.synchronize(accountId);
    final remote = await transport.downloadLatestEncryptedSnapshot(accountId);
    await expectLater(
      firstRecovery.codec.decrypt(
        accountId: accountId,
        encryptedBlob: remote!.encryptedBlob,
        recoveryKey: await const _FixedRecoveryKeyProvider(
          99,
        ).recoveryKey(accountId),
      ),
      throwsA(
        isA<PqcRecoveryException>().having(
          (error) => error.failure,
          'failure',
          PqcRecoveryFailure.corrupted,
        ),
      ),
    );

    final forkVault = PqcIntegrityKeyVault(store: PqcMemoryAtomicStore());
    await forkVault.saveDeviceKeyset(
      accountId: accountId,
      keyset: engine.generateDeviceKeyset('fork-phone'),
      makeCurrent: true,
    );
    final forkRecovery = PqcRecoveryCoordinator(
      vault: forkVault,
      transport: transport,
      keyProvider: keyProvider,
    );
    await expectLater(
      forkRecovery.synchronize(accountId),
      throwsA(
        isA<PqcRecoveryException>().having(
          (error) => error.failure,
          'failure',
          PqcRecoveryFailure.revisionConflict,
        ),
      ),
    );
  });

  test(
    'replay guard distinguishes duplicate from message-id collision',
    () async {
      final guard = PqcReplayGuard(PqcMemoryReplayStore());
      final binding = pqcAccountBinding(accountId);
      expect(
        await guard.claim(
          accountBinding: binding,
          conversationId: 7,
          messageId: 'm-1',
          encryptedPayload: 'cipher-a',
        ),
        PqcReplayDecision.accepted,
      );
      expect(
        await guard.claim(
          accountBinding: binding,
          conversationId: 7,
          messageId: 'm-1',
          encryptedPayload: 'cipher-a',
        ),
        PqcReplayDecision.duplicate,
      );
      expect(
        await guard.claim(
          accountBinding: binding,
          conversationId: 7,
          messageId: 'm-1',
          encryptedPayload: 'cipher-b',
        ),
        PqcReplayDecision.messageIdCollision,
      );
    },
  );

  test('atomic replay claims survive restarts and racing delivery', () async {
    final store = PqcMemoryAtomicStore();
    final firstGuard = PqcReplayGuard(PqcAtomicReplayStore(store));
    final binding = pqcAccountBinding(accountId);
    final decisions = await Future.wait([
      firstGuard.claim(
        accountBinding: binding,
        conversationId: 7,
        messageId: 'durable-message',
        encryptedPayload: 'cipher-a',
      ),
      firstGuard.claim(
        accountBinding: binding,
        conversationId: 7,
        messageId: 'durable-message',
        encryptedPayload: 'cipher-a',
      ),
    ]);
    expect(
      decisions.where((item) => item == PqcReplayDecision.accepted),
      hasLength(1),
    );
    expect(
      decisions.where((item) => item == PqcReplayDecision.duplicate),
      hasLength(1),
    );

    final restartedGuard = PqcReplayGuard(PqcAtomicReplayStore(store));
    expect(
      await restartedGuard.claim(
        accountBinding: binding,
        conversationId: 7,
        messageId: 'durable-message',
        encryptedPayload: 'cipher-b',
      ),
      PqcReplayDecision.messageIdCollision,
    );
  });

  test(
    'health monitor blocks writer until key and recovery are durable',
    () async {
      final health = PqcCryptoHealthMonitor();
      final vault = PqcIntegrityKeyVault(store: PqcMemoryAtomicStore());
      final recovery = PqcRecoveryCoordinator(
        vault: vault,
        transport: PqcMemoryRecoveryRepository(),
        keyProvider: const _FixedRecoveryKeyProvider(41),
        healthMonitor: health,
      );
      final runtime = PqcSecureRuntime(
        manager: PqcEngineManager(
          decoders: [engine],
          activeWriterId: engine.engineId,
          writerEnabled: true,
          releaseProfile: PqcReleaseProfiles.v25,
        ),
        vault: vault,
        recovery: recovery,
        replayGuard: PqcReplayGuard(PqcMemoryReplayStore()),
        healthMonitor: health,
      );
      await runtime.initializeAccount(accountId);
      expect(
        () => runtime.requireWriter(
          kind: PqcConversationKind.private,
          remote: capabilities,
        ),
        throwsA(isA<PqcCryptoHealthException>()),
      );

      await runtime.rotateDeviceKeyset(accountId: accountId, deviceId: 'phone');
      expect(
        runtime.requireWriter(
          kind: PqcConversationKind.private,
          remote: capabilities,
        ),
        same(engine),
      );
      expect(health.snapshot.isSafeToWrite, isTrue);
    },
  );
}
