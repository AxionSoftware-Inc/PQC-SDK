import 'package:pqc_engine_sdk/pqc_engine_sdk.dart';

void main() {
  final engine = PqcV2Engine();
  if (engine.protocolVersion != PqcV2Wire.protocolVersion) {
    throw StateError('Unexpected protocol version.');
  }
}
