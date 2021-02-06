using System;
using System.Collections.Generic;
using System.Text;
using libsignalservice.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace libsignal_service_dotnet_tests.util
{
    [TestClass]
    public class UtilTests
    {
        [TestMethod]
        public void JavaUUIDToCSharpGuid()
        {
            long mostSigBits = 4822678189205111;
            long leastSigBits = -8603657889541918977;

            Assert.AreEqual(new Guid("00112233-4455-6677-8899-aabbccddeeff"), Util.JavaUUIDToCSharpGuid(mostSigBits, leastSigBits));
        }
    }
}
