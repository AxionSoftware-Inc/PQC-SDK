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

## Required host controls

Private keys must be encrypted at rest and written atomically. Publishing a
public key before its private counterpart and recovery snapshot are durable
can create permanent history loss. Rotation must mark an old keyset read-only,
not delete it.

Recovery snapshots need an account binding, monotonically increasing revision,
authenticated encryption, SHA-256 integrity value and conflict handling. The
recovery transport only receives encrypted blobs.

Replay prevention belongs to the message store because it owns message ids and
transaction boundaries. Reject an already accepted `(conversationId,
messageId)` pair before presenting the plaintext.

Never log plaintext, private keys, shared secrets, attachment descriptors or
full encrypted recovery blobs. Error telemetry should contain only a stable
error category and non-secret correlation id.

## Cryptographic changes

PQCv2 constants and serialization are frozen. Changing a prefix, algorithm
label, field, field order, signing context, HKDF input or nonce derivation
requires a new engine version and decoder. Never silently mutate V2.

Security reports: contact the repository owner through a private channel. Do
not open a public issue containing keys or production payloads.
