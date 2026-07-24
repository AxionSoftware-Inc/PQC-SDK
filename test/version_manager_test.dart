import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';
import 'package:test/test.dart';

void main() {
  final engine = PqcV2Engine();
  const capabilities = PqcRemoteCapabilities(
    privateReadPrefixes: {PqcV2Wire.privatePrefix},
    groupReadPrefixes: {PqcV2Wire.groupPrefix},
    privateWritePrefixes: {PqcV2Wire.privatePrefix},
    groupWritePrefixes: {PqcV2Wire.groupPrefix},
    attachmentCipherVersions: {PqcV2Wire.attachmentCipherVersion},
    minimumDecoderVersion: 2,
  );

  test('writer is closed unless explicitly enabled', () {
    final manager = PqcEngineManager(
      decoders: [engine],
      activeWriterId: engine.engineId,
    );
    expect(
      () => manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: capabilities,
      ),
      throwsA(isA<PqcCompatibilityException>()),
    );
  });

  test('capability gate allows only advertised format', () {
    final manager = PqcEngineManager(
      decoders: [engine],
      activeWriterId: engine.engineId,
      writerEnabled: true,
    );
    expect(
      manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: capabilities,
      ),
      same(engine),
    );
    expect(
      () => manager.requireWriter(
        kind: PqcConversationKind.group,
        remote: const PqcRemoteCapabilities(
          privateReadPrefixes: {PqcV2Wire.privatePrefix},
          groupReadPrefixes: {},
          privateWritePrefixes: {PqcV2Wire.privatePrefix},
          groupWritePrefixes: {},
          attachmentCipherVersions: {PqcV2Wire.attachmentCipherVersion},
          minimumDecoderVersion: 2,
        ),
      ),
      throwsA(isA<PqcCompatibilityException>()),
    );
  });

  test('rejects read/write asymmetry and decoder downgrade', () {
    final manager = PqcEngineManager(
      decoders: [engine],
      activeWriterId: engine.engineId,
      writerEnabled: true,
    );
    expect(
      () => manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: const PqcRemoteCapabilities(
          privateReadPrefixes: {},
          groupReadPrefixes: {PqcV2Wire.groupPrefix},
          privateWritePrefixes: {PqcV2Wire.privatePrefix},
          groupWritePrefixes: {PqcV2Wire.groupPrefix},
          attachmentCipherVersions: {PqcV2Wire.attachmentCipherVersion},
          minimumDecoderVersion: 2,
        ),
      ),
      throwsA(isA<PqcCompatibilityException>()),
    );
    expect(
      () => manager.requireWriter(
        kind: PqcConversationKind.private,
        remote: const PqcRemoteCapabilities(
          privateReadPrefixes: {PqcV2Wire.privatePrefix},
          groupReadPrefixes: {PqcV2Wire.groupPrefix},
          privateWritePrefixes: {PqcV2Wire.privatePrefix},
          groupWritePrefixes: {PqcV2Wire.groupPrefix},
          attachmentCipherVersions: {PqcV2Wire.attachmentCipherVersion},
          minimumDecoderVersion: 3,
        ),
      ),
      throwsA(isA<PqcCompatibilityException>()),
    );
  });

  test('routes recognized formats and rejects unknown payloads', () {
    final manager = PqcEngineManager(decoders: [engine]);
    expect(
      manager.resolveDecoder(
        kind: PqcConversationKind.private,
        payload: '${PqcV2Wire.privatePrefix}:payload',
      ),
      same(engine),
    );
    expect(
      () => manager.resolveDecoder(
        kind: PqcConversationKind.private,
        payload: 'pqc:v99:payload',
      ),
      throwsA(isA<PqcCompatibilityException>()),
    );
  });

  test('rejects duplicate engine ids', () {
    expect(
      () => PqcEngineManager(decoders: [engine, PqcV2Engine()]),
      throwsArgumentError,
    );
  });
}
