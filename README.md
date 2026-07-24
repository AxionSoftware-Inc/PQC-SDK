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
      url: git@github.com:AxionSoftware-Inc/PQC_Flutter.git
      ref: pqc-engine-sdk-v0.1.0-dev.1
      path: packages/pqc_engine_sdk
```

For paid distribution, publish the same tagged package to a private Dart
package registry and issue registry credentials to licensed customers.

## Basic private-message use

```dart
import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';

final engine = PqcV2Engine();
final alice = engine.primitives.generateDeviceKeyset('alice-phone');

final payload = await engine.private.encrypt(
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
  decoders: [PqcV2Engine()],
  activeWriterId: 'pqc-v2',
  writerEnabled: true,
);

final writer = manager.requireWriter(
  kind: PqcConversationKind.private,
  remote: serverCapabilities,
);
```

The host should leave `writerEnabled` false until its recovery, real-device
and server-capability tests pass. A recognized payload is never retried with a
different protocol after authentication fails.

## Host responsibilities

The integrating application is responsible for:

1. assigning a stable account id and device id;
2. atomically persisting the private keyset before publishing its public key;
3. retaining old keysets as read-only history after rotation;
4. maintaining trusted current and historical signing public keys;
5. encrypting, hashing, versioning and conflict-checking recovery snapshots;
6. restoring keys before history decryption after login or reinstall;
7. persisting group epochs before acknowledging group messages;
8. replay protection and unique message ids at the transport/database layer;
9. upload/download streaming, retries and attachment size policy;
10. keeping logs free of plaintext and secret key material.

See [SECURITY.md](SECURITY.md) and [MIGRATION.md](MIGRATION.md).

## Verification

```sh
dart pub get
dart analyze
dart test
dart compile js tool/web_smoke.dart -O2 -o /tmp/pqc_engine_sdk.js
```

The tests use the real ML-KEM, ML-DSA and AES-GCM implementations.
