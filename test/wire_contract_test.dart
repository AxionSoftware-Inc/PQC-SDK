import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';
import 'package:test/test.dart';

void main() {
  test('PQCv2 wire contract remains frozen', () {
    expect(PqcV2Wire.protocolVersion, 2);
    expect(PqcV2Wire.privatePrefix, 'pqc:v2');
    expect(PqcV2Wire.groupPrefix, 'group:v2');
    expect(PqcV2Wire.groupWrapPrefix, 'group-wrap:pqc:v2');
    expect(PqcV2Wire.privateAlgorithm, 'ml-kem-768+a256gcm+ml-dsa-65');
    expect(PqcV2Wire.groupAlgorithm, 'a256gcm+group-ml-kem-768');
    expect(PqcV2Wire.groupEnvelopeAlgorithm, 'group-ml-kem-768-aesgcm-v2');
    expect(PqcV2Wire.attachmentCipherVersion, 'attachment:v2');
  });
}
