# PQC Engine SDK

Pure Dart post-quantum cryptography engine for Axion products and licensed
integrators. It contains cryptographic protocol code only. It has no Flutter,
UI, HTTP, login, database, file-system or platform-storage dependency.

## What is included

- ML-KEM-768 recipient key wrapping
- ML-DSA-65 sender signatures
- AES-256-GCM content encryption
- frozen PQCv2 private-message reader/writer
- frozen PQCv2 group-message and group-epoch reader/writer
- byte-oriented PQCv2 attachment encryption
- historical keyset decoding
- explicit protocol registry and production write gate
- capability negotiation checks
- host interfaces for secure key storage and encrypted recovery transport
- atomic, checksummed key-vault orchestration over a host storage adapter
- key continuity that retains rotated keys as historical decoders
- encrypted account-bound recovery with monotonic revision conflict checks
- automatic reinstall restore and key-missing decrypt retry
- health-gated writes and durable replay/message-id collision protection

## Platform support

- Flutter Android/iOS/macOS/Windows/Linux
- Dart server and command-line applications
- Dart web compiled to JavaScript

The SDK never chooses a platform persistence mechanism. A host application
must implement `PqcKeyRepository` using Keychain/Keystore, an encrypted
database, IndexedDB, an HSM, or another appropriate facility.

## Install from a private Git tag

```yaml
dependencies:
  pqc_engine_sdk:
    git:
      url: git@github.com:AxionSoftware-Inc/PQC-SDK.git
      ref: sdk-v2.5.0-freeze
```

For paid distribution, grant repository access to licensed customers or
publish the same tagged package to a private Dart package registry.

## Basic private-message use

```dart
import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';

final decoder = PqcV2Engine();
final writer = PqcV25Writer();
final alice = writer.primitives.generateDeviceKeyset('alice-phone');

final payload = await writer.private.encrypt(
  conversation: const PqcConversation(id: 42, type: 'private'),
  plaintext: 'Assalomu alaykum',
  sender: alice,
  recipientDevices: [bobPublicKey],
);

final result = await engine.private.decrypt(
  conversation: const PqcConversation(id: 42, type: 'private'),
  payload: payload,
  localKeysets: [bobCurrentKeyset, ...bobHistoricalKeysets],
  trustedSigningKeysByDevice: trustedSenderKeys,
);
```

Do not treat `PqcDecodeError.keyMissing` as corrupted history. Restore the
account-scoped key snapshot, load historical keysets, and retry the same
payload.

## Production writer gate

```dart
final manager = PqcEngineManager(
  decoders: [PqcV2Engine()], // frozen history reader
  activeWriter: PqcV25Writer(),
  writerEnabled: true,
  releaseProfile: PqcReleaseProfiles.v25,
);

final writer = manager.requireWriter(
  kind: PqcConversationKind.private,
  remote: serverCapabilities,
);
```

The host should leave `writerEnabled` false until its recovery, real-device
and server-capability tests pass. A recognized payload is never retried with a
different protocol after authentication fails.

`releaseId: 2.5.0` and `wireProtocol: v2` are independent values. V2.5 writes
immutable `pqc:v2` / `group:v2` payloads through its dedicated writer while
the frozen V2 decoder remains permanently registered for history.

## Secure runtime

```dart
final atomicStore = MyHardwareBackedAtomicStore();
final vault = PqcIntegrityKeyVault(store: atomicStore);
final health = PqcCryptoHealthMonitor();
final recovery = PqcRecoveryCoordinator(
  vault: vault,
  transport: MyConditionalRecoveryTransport(),
  keyProvider: MyAccountRecoveryKeyProvider(),
  authorizer: MyFreshDeviceRecoveryAuthorizer(),
  healthMonitor: health,
);
final runtime = PqcSecureRuntime(
  manager: manager,
  vault: vault,
  recovery: recovery,
  replayGuard: PqcReplayGuard(PqcAtomicReplayStore(atomicStore)),
  healthMonitor: health,
);

await runtime.initializeAccount(accountId); // login/reinstall restore
final writer = await runtime.prepareWriter(
  accountId: accountId,
  kind: PqcConversationKind.private,
  remote: serverCapabilities,
);
```

`rotateDeviceKeyset` returns only after the private key is atomically durable
and its encrypted recovery revision is synchronized. Publish the returned
public key only after that future completes. `persistGroupEpochBeforeAck`
provides the equivalent ordering guarantee for group epochs.

## Host responsibilities

The integrating application is responsible for:

1. assigning a stable account id and device id;
2. implementing `PqcProductionAtomicStore` with encrypted-at-rest,
   hardware-backed key protection and a real atomic durable transaction;
3. providing a `PqcRecoveryAccessAuthorizer` that requires a fresh,
   device-bound, short-lived proof rather than accepting a session token;
4. publishing public keys only after `rotateDeviceKeyset` succeeds;
5. maintaining trusted current and historical signing public keys;
6. supplying a protected 32-byte account recovery key;
7. implementing conditional recovery upload for race-free server sync;
8. persisting group epochs before acknowledging group messages;
9. assigning stable unique message ids before using the replay guard;
10. upload/download streaming, retries and attachment size policy;
11. keeping logs free of plaintext and secret key material.

See [SECURITY.md](SECURITY.md) and [MIGRATION.md](MIGRATION.md).

## Verification

```sh
dart pub get
dart analyze
dart test
dart compile js tool/web_smoke.dart -O2 -o /tmp/pqc_engine_sdk.js
```

The tests use the real ML-KEM, ML-DSA and AES-GCM implementations.
