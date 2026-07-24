import 'dart:convert';
import 'dart:math';

import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';
import 'package:test/test.dart';

void main() {
  test('malformed private payloads never escape as exceptions', () async {
    final engine = PqcV2Engine();
    final local = engine.primitives.generateDeviceKeyset('local');
    const conversation = PqcConversation(id: 9, type: 'private');
    final malformed = <String>[
      '',
      'plain text',
      'pqc:v1:anything',
      '${PqcV2Wire.privatePrefix}:',
      '${PqcV2Wire.privatePrefix}:!',
      '${PqcV2Wire.privatePrefix}:${base64UrlEncode(utf8.encode('[]'))}',
      '${PqcV2Wire.privatePrefix}:${base64UrlEncode(utf8.encode('{}'))}',
    ];

    for (final payload in malformed) {
      final result = await engine.private.decrypt(
        conversation: conversation,
        payload: payload,
        localKeysets: [local],
        trustedSigningKeysByDevice: const {},
      );
      expect(result, isA<PqcDecodeError>());
    }
  });

  test('random payload mutations cannot authenticate', () async {
    final engine = PqcV2Engine();
    final sender = engine.primitives.generateDeviceKeyset('sender');
    final recipient = engine.primitives.generateDeviceKeyset('recipient');
    const conversation = PqcConversation(id: 10, type: 'private');
    final payload = await engine.private.encrypt(
      conversation: conversation,
      plaintext: 'mutation target',
      sender: sender,
      recipientDevices: [recipient.publicKey],
    );
    final random = Random(20260724);

    for (var iteration = 0; iteration < 24; iteration++) {
      final bytes = utf8.encode(payload).toList();
      final index =
          PqcV2Wire.privatePrefix.length +
          1 +
          random.nextInt(bytes.length - PqcV2Wire.privatePrefix.length - 1);
      bytes[index] = bytes[index] == 65 ? 66 : 65;
      final result = await engine.private.decrypt(
        conversation: conversation,
        payload: utf8.decode(bytes),
        localKeysets: [recipient],
        trustedSigningKeysByDevice: {
          sender.deviceId: {sender.signingPublicKeyBase64},
        },
      );
      expect(result, isA<PqcDecodeError>());
    }
  });

  test('attachment chunk index is cryptographically bound', () async {
    final engine = PqcV2Engine();
    final descriptor = engine.attachment.generateDescriptor();
    final encrypted = await engine.attachment.encryptChunk(
      plaintext: List<int>.generate(100, (index) => index),
      descriptor: descriptor,
      chunkIndex: 1,
    );
    await expectLater(
      engine.attachment.decryptChunk(
        ciphertext: encrypted.ciphertext,
        descriptor: descriptor,
        chunkIndex: 2,
      ),
      throwsA(anything),
    );
  });
}
