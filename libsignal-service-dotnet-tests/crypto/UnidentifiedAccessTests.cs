using libsignalservicedotnet.crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using org.whispersystems.curve25519.csharp;

namespace libsignal_service_dotnet_tests.crypto
{
    [TestClass]
    public class UnidentifiedAccessTests
    {
        private readonly byte[] EXPECTED_RESULT = new byte[] { 0x5a, 0x72, 0x3a, 0xce, 0xe5, 0x2c, 0x5e, 0xa0, 0x2b, 0x92, 0xa3, 0xa3, 0x60, 0xc0, 0x95, 0x95 };

        [TestMethod]
        public void TestKeyDerivation()
        {
            byte[] key = new byte[32];
            Arrays.fill(key, 0x02);

            byte[] result = UnidentifiedAccess.DeriveAccessKeyFrom(key);
            CollectionAssert.AreEqual(EXPECTED_RESULT, result);
        }
    }
}
