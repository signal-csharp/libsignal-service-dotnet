using libsignalservice.messages;
using serialize.protos;

namespace libsignalservice.serialize
{
    public static class SignalServiceMetadataProtobufSerializer
    {
        public static MetadataProto ToProtobuf(SignalServiceMetadata metadata)
        {
            return new MetadataProto()
            {
                Address = SignalServiceAddressProtobufSerializer.ToProtobuf(metadata.Sender),
                SenderDevice = metadata.SenderDevice,
                NeedsReceipt = metadata.NeedsReceipt,
                Timestamp = metadata.Timestamp
            };
        }

        public static SignalServiceMetadata FromProtobuf(MetadataProto metadata)
        {
            return new SignalServiceMetadata(SignalServiceAddressProtobufSerializer.FromProtobuf(metadata.Address),
                metadata.SenderDevice,
                metadata.Timestamp,
                metadata.NeedsReceipt);
        }
    }
}
