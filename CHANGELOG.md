# Changelog

## 0.2.6

- Made production key storage fail closed unless the host proves encrypted,
  hardware-backed and atomically durable persistence.
- Added mandatory fresh device-bound authorization for recovery reads/writes.
- Restricted insecure memory/recovery bypasses to explicit non-product tests.

## 0.2.5

- Strictly separated application release `2.5.0` from wire protocol `v2`.
- Added a dedicated V2.5 active writer while retaining the frozen V2 decoder.
- Added device-revoke retirement without historical-key deletion.
- Expanded relogin, revoke and multi-epoch group-rekey regression coverage.

## 0.2.0

- Added V2.5 release profile while preserving the frozen V2 wire protocol.
- Added an integrity-checked atomic key vault and explicit continuity guard.
- Added encrypted, account-bound, revisioned recovery coordination.
- Added login/reinstall restore and automatic key-missing decrypt retry.
- Added crypto health gating before encrypted writes.
- Added durable replay and message-id collision protection.
- Added power-loss, concurrency, recovery tamper and reinstall chaos tests.

## 0.1.0-dev.3

- Add validated, read-only PQCv2 group payload metadata inspection for host
  epoch resolution.

## 0.1.0-dev.2

- Publish as a standalone private repository.
- Correct package repository metadata and installation instructions.

## 0.1.0-dev.1

- Initial pure Dart engine package.
- Frozen PQCv2 private, group and attachment codecs.
- Historical keyset decoding and explicit recovery classification.
- Protocol registry, capability negotiation and writer gate.
- Secure-storage and encrypted-recovery host interfaces.
- VM tests and JavaScript compile verification.
