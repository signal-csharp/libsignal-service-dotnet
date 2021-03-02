using System;
using System.Collections.Generic;
using System.Text;
using libsignalservice.push;
using libsignalservice.serialize;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using serialize.protos;

namespace libsignal_service_dotnet_tests.serialize
{
    [TestClass]
    public class SignalServiceAddressProtobufSerializerTest
    {
        [TestMethod]
        public void Serialize_And_Deserialize_Uuid_Address()
        {
            SignalServiceAddress address = new SignalServiceAddress(Guid.NewGuid(), null, null);
            AddressProto addressProto = SignalServiceAddressProtobufSerializer.ToProtobuf(address);
            SignalServiceAddress deserialized = SignalServiceAddressProtobufSerializer.FromProtobuf(addressProto);

            Assert.AreEqual(address, deserialized);
        }

        [TestMethod]
        public void Serialize_And_Deserialize_E164_Address()
        {
            SignalServiceAddress address = new SignalServiceAddress(null, "+15552345678", null);
            AddressProto addressProto = SignalServiceAddressProtobufSerializer.ToProtobuf(address);
            SignalServiceAddress deserialized = SignalServiceAddressProtobufSerializer.FromProtobuf(addressProto);

            Assert.AreEqual(address, deserialized);
        }

        [TestMethod]
        public void Serialize_And_Deserialize_Both_Address()
        {
            SignalServiceAddress address = new SignalServiceAddress(Guid.NewGuid(), "+15552345678", null);
            AddressProto addressProto = SignalServiceAddressProtobufSerializer.ToProtobuf(address);
            SignalServiceAddress deserialized = SignalServiceAddressProtobufSerializer.FromProtobuf(addressProto);

            Assert.AreEqual(address, deserialized);
        }

        [TestMethod]
        public void Serialize_And_Deserialize_Both_Address_With_Relay()
        {
            SignalServiceAddress address = new SignalServiceAddress(Guid.NewGuid(), "+15552345678", "relay");
            AddressProto addressProto = SignalServiceAddressProtobufSerializer.ToProtobuf(address);
            SignalServiceAddress deserialized = SignalServiceAddressProtobufSerializer.FromProtobuf(addressProto);

            Assert.AreEqual(address, deserialized);
        }
    }
}
