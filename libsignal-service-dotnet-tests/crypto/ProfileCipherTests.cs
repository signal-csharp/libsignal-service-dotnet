using System.IO;
using System.Text;
using libsignalservice.crypto;
using libsignalservice.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace libsignal_service_dotnet_tests.crypto
{
    [TestClass]
    public class ProfileCipherTests
    {
        [TestMethod]
        public void TestEncryptDecrypt()
        {
            byte[] key = Util.GetSecretBytes(32);
            ProfileCipher cipher = new ProfileCipher(key);
            byte[] name = cipher.EncryptName(Encoding.UTF8.GetBytes("Clement Duval"), 26);
            byte[] plaintext = cipher.DecryptName(name);
            Assert.AreEqual("Clement Duval", Encoding.UTF8.GetString(plaintext));
        }

        [TestMethod]
        public void TestEmpty()
        {
            byte[] key = Util.GetSecretBytes(32);
            ProfileCipher cipher = new ProfileCipher(key);
            byte[] name = cipher.EncryptName(Encoding.UTF8.GetBytes(string.Empty), 26);
            byte[] plaintext = cipher.DecryptName(name);

            Assert.AreEqual(0, plaintext.Length);
        }

        [TestMethod]
        public void TestStreams()
        {
            byte[] key = Util.GetSecretBytes(32);
            MemoryStream baos = new MemoryStream();
            ProfileCipherOutputStream _out = new ProfileCipherOutputStream(baos, key);

            _out.Write(Encoding.UTF8.GetBytes("This is an avatar"));
            _out.Flush();
            _out.Dispose();

            MemoryStream bais = new MemoryStream(baos.ToArray());
            ProfileCipherInputStream _in = new ProfileCipherInputStream(bais, key);

            MemoryStream result = new MemoryStream();
            byte[] buffer = new byte[2048];

            int read;

            while ((read = _in.Read(buffer)) != 0)
            {
                result.Write(buffer, 0, read);
            }

            Assert.AreEqual("This is an avatar", Encoding.UTF8.GetString(result.ToArray()));
        }
    }
}
