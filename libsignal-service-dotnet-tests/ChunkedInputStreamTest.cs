using libsignalservice.messages.multidevice;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace libsignal_service_dotnet_tests
{
    [TestClass]
    public class ChunkedInputStreamTest
    {
        [TestMethod]
        public void TestReadRawVarint32()
        {
            MemoryStream ms = new MemoryStream();
            byte[] input;
            int i;

            input = new byte[] { 216, 1, 0, 0, 0, 0, 0,};
            ms.Write(input, 0, input.Length);
            ms.Position = 0;
            
            i = new ChunkedInputStream(ms).ReadRawVarint32();
            ms.Position = 0;
            Assert.AreEqual(216, i);


            input = new byte[] { 172, 2, 0xff, 0xff, 0, 0, 0, };
            ms.Write(input, 0, input.Length);
            ms.Position = 0;

            i = new ChunkedInputStream(ms).ReadRawVarint32();
            ms.Position = 0;
            Assert.AreEqual(300, i);


            input = new byte[] { 5, 0xff, 0xff, 0xff, 0, 0, 0, };
            ms.Write(input, 0, input.Length);
            ms.Position = 0;

            i = new ChunkedInputStream(ms).ReadRawVarint32();
            ms.Position = 0;
            Assert.AreEqual(5, i);


            input = new byte[] { 199, 232, 67, 0xff, 0, 0, 0, };
            ms.Write(input, 0, input.Length);
            ms.Position = 0;

            i = new ChunkedInputStream(ms).ReadRawVarint32();
            ms.Position = 0;
            Assert.AreEqual(1111111, i);


            input = new byte[] { 128, 1, 0xff, 0xff, 0, 0, 0, };
            ms.Write(input, 0, input.Length);
            ms.Position = 0;

            i = new ChunkedInputStream(ms).ReadRawVarint32();
            ms.Position = 0;
            Assert.AreEqual(128, i);
        }
    }
}
