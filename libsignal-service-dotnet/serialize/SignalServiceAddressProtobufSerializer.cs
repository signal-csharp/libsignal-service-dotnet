using libsignalservice.push;
using serialize.protos;

namespace libsignalservice.serialize
{
    public static class SignalServiceAddressProtobufSerializer
    {
        public static AddressProto ToProtobuf(SignalServiceAddress signalServiceAddress)
        {
            AddressProto builder = new AddressProto();
            if (signalServiceAddress.E164number != null)
            {
                builder.E164 = signalServiceAddress.E164number;
            }
            // TODO: Finish the UUID changes
            if (signalServiceAddress.Relay != null)
            {
                builder.Relay = signalServiceAddress.Relay;
            }

            return builder;
        }

        public static SignalServiceAddress FromProtobuf(AddressProto addressProto)
        {
            // TODO: Finish the UUID changes
            string? number = addressProto.HasE164 ? addressProto.E164 : null;
            string? relay = addressProto.HasRelay ? addressProto.Relay : null;
            return new SignalServiceAddress(number, relay);
        }
    }
}
