using System;
using Google.Protobuf;
using libsignalservice.push;
using libsignalservice.util;
using serialize.protos;

namespace libsignalservice.serialize
{
    public static class SignalServiceAddressProtobufSerializer
    {
        public static AddressProto ToProtobuf(SignalServiceAddress signalServiceAddress)
        {
            AddressProto builder = new AddressProto();
            if (signalServiceAddress.GetNumber() != null)
            {
                builder.E164 = signalServiceAddress.E164;
            }
            if (signalServiceAddress.Uuid.HasValue)
            {
                builder.Uuid = ByteString.CopyFrom(UuidUtil.ToByteArray(signalServiceAddress.Uuid.Value));
            }
            if (signalServiceAddress.Relay != null)
            {
                builder.Relay = signalServiceAddress.Relay;
            }
            return builder;
        }

        public static SignalServiceAddress FromProtobuf(AddressProto addressProto)
        {
            Guid? uuid = addressProto.HasUuid ? UuidUtil.ParseOrThrow(addressProto.Uuid.ToByteArray()) : (Guid?)null;
            string? number = addressProto.HasE164 ? addressProto.E164 : null;
            string? relay = addressProto.HasRelay ? addressProto.Relay : null;
            return new SignalServiceAddress(uuid, number, relay);
        }
    }
}
