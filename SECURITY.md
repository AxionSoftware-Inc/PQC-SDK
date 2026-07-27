# Security boundary

## Guarantees inside the SDK

- strict conversation id/type binding;
- sender-signature verification against host-supplied trust records;
- recipient device and keyset binding;
- authenticated content and attachment chunks;
- historical private-key decoding;
- explicit missing-key, untrusted-sender, binding and corruption outcomes;
- no protocol fallback after a recognized payload fails authentication;
- remote capability checks before a writer is returned.
- checksummed atomic key-vault records with compare-and-set retries;
- old-key retention and keyset/group-epoch rebinding rejection;
- account-bound authenticated recovery envelopes and revision conflicts;
- automatic key-missing restore/retry without protocol downgrade;
- health-gated writes and durable replay/message-id collision claims.

## Required host controls

Production hosts must implement `PqcProductionAtomicStore`. The SDK refuses to
construct a production vault unless the adapter declares encrypted-at-rest,
hardware-backed key protection and atomic durability. Ciphertext and its master
key must never share the same preferences/database namespace. Test-only memory
stores require the explicit `allowInsecureStoreForTesting` switch and that
switch is rejected in Dart product mode.

The host must protect the 32-byte recovery master key and implement a
conditional recovery transport. `PqcRecoveryCoordinator` additionally requires
a `PqcRecoveryAccessAuthorizer` which validates a fresh, device-bound,
short-lived proof for recovery reads and writes. A normal login token alone is
not sufficient. The recovery server receives only an authenticated encrypted
envelope, its revision and SHA-256 value.

Use `PqcAtomicReplayStore` with a durable adapter before presenting newly
received plaintext. Duplicate ciphertext is classified separately from reuse
of the same message id for different ciphertext.

Never log plaintext, private keys, shared secrets, attachment descriptors or
full encrypted recovery blobs. Error telemetry should contain only a stable
error category and non-secret correlation id.

## Cryptographic changes

PQCv2 constants and serialization are frozen. Changing a prefix, algorithm
label, field, field order, signing context, HKDF input or nonce derivation
requires a new engine version and decoder. Never silently mutate V2.

Security reports: contact the repository owner through a private channel. Do
not open a public issue containing keys or production payloads.
