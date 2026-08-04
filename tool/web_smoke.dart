import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';

void main() {
  final v2 = PqcV2Engine();
  final v3 = PqcV3Engine();
  if (v2.protocolVersion != PqcV2Wire.protocolVersion ||
      v3.protocolVersion != PqcV3Wire.protocolVersion) {
    throw StateError('Unexpected protocol version.');
  }
}
