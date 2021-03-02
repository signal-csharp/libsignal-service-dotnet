using System;
using libsignalservice.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace libsignal_service_dotnet_tests.util
{
    [TestClass]
    public class UuidUtilTests
    {
        [TestMethod]
        public void ToByteArray()
        {
            Guid uuid = new Guid("67dfd496-ea02-4720-b13d-83a462168b1d");

            byte[] serialized = UuidUtil.ToByteArray(uuid);

            CollectionAssert.AreEqual(Hex.FromStringCondensed("67dfd496ea024720b13d83a462168b1d"), serialized);
        }

        [TestMethod]
        public void ToByteArray_AlternativeValues()
        {
            Guid uuid = new Guid("b70df6ac-3b21-4b39-a514-613561f51e2a");

            byte[] serialized = UuidUtil.ToByteArray(uuid);

            CollectionAssert.AreEqual(Hex.FromStringCondensed("b70df6ac3b214b39a514613561f51e2a"), serialized);
        }

        [TestMethod]
        public void ParseOrThrow_From_ByteArray()
        {
            byte[] bytes = Hex.FromStringCondensed("3dc48790568b49c19bd6ab6604a5bc32");

            Guid uuid = UuidUtil.ParseOrThrow(bytes);

            Assert.AreEqual("3dc48790-568b-49c1-9bd6-ab6604a5bc32", uuid.ToString());
        }

        [TestMethod]
        public void ParseOrThrow_From_ByteArray_AlternativeValues()
        {
            byte[] bytes = Hex.FromStringCondensed("b83dfb0b67f141aa992e030c167cd011");

            Guid uuid = UuidUtil.ParseOrThrow(bytes);

            Assert.AreEqual("b83dfb0b-67f1-41aa-992e-030c167cd011", uuid.ToString());
        }

        [TestMethod]
        public void JavaUUIDToCSharpGuid()
        {
            long mostSigBits = 4822678189205111;
            long leastSigBits = -8603657889541918977;

            Assert.AreEqual(new Guid("00112233-4455-6677-8899-aabbccddeeff"), UuidUtil.JavaUUIDToCSharpGuid(mostSigBits, leastSigBits));
        }

        [TestMethod]
        public void GetMostSignificantBits()
        {
            Guid guid = new Guid("00112233-4455-6677-8899-aabbccddeeff");
            Assert.AreEqual(4822678189205111, guid.GetMostSignificantBits());
        }

        [TestMethod]
        public void GetLeastSignificantBits()
        {
            Guid guid = new Guid("00112233-4455-6677-8899-aabbccddeeff");
            Assert.AreEqual(-8603657889541918977, guid.GetLeastSignificantBits());
        }
    }
}
