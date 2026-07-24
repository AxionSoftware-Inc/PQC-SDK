import 'models.dart';
import 'primitives.dart';
import 'v2_attachment_codec.dart';
import 'v2_group_codec.dart';
import 'v2_private_codec.dart';

abstract interface class PqcEngine {
  String get engineId;
  int get protocolVersion;
  String get privatePrefix;
  String get groupPrefix;
  Set<String> get attachmentCipherVersions;

  bool recognizesPrivate(String payload);
  bool recognizesGroup(String payload);
}

class PqcV2Engine implements PqcEngine {
  PqcV2Engine({PqcPrimitiveSuite? primitives})
    : primitives = primitives ?? DartPqcPrimitiveSuite() {
    private = PqcV2PrivateCodec(this.primitives);
    group = PqcV2GroupCodec(this.primitives);
    attachment = PqcV2AttachmentCodec(this.primitives);
  }

  final PqcPrimitiveSuite primitives;
  late final PqcV2PrivateCodec private;
  late final PqcV2GroupCodec group;
  late final PqcV2AttachmentCodec attachment;

  @override
  String get engineId => 'pqc-v2';

  @override
  int get protocolVersion => PqcV2Wire.protocolVersion;

  @override
  String get privatePrefix => PqcV2Wire.privatePrefix;

  @override
  String get groupPrefix => PqcV2Wire.groupPrefix;

  @override
  Set<String> get attachmentCipherVersions => const {
    PqcV2Wire.attachmentCipherVersion,
  };

  @override
  bool recognizesPrivate(String payload) =>
      payload.startsWith('$privatePrefix:');

  @override
  bool recognizesGroup(String payload) => payload.startsWith('$groupPrefix:');
}
