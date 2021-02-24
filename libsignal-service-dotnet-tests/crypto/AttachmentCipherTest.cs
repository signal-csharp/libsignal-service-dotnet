using System;
using System.IO;
using System.Text;
using libsignal;
using libsignal.kdf;
using libsignalservice.crypto;
using libsignalservice.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace libsignal_service_dotnet_tests.crypto
{
    [TestClass]
    public class AttachmentCipherTest
    {
        [TestMethod]
        public void Test_Attachment_EncryptDecrypt()
        {
            byte[] key = Util.GetSecretBytes(64);
            byte[] plaintextInput = Encoding.UTF8.GetBytes("Peter Parker");
            EncryptResult encryptResult = EncryptData(plaintextInput, key);
            string cipherFile = WriteToFile(encryptResult.ciphertext);
            Stream inputStream = AttachmentCipherInputStream.CreateForAttachment(File.Open(cipherFile, FileMode.Open), plaintextInput.Length, key, encryptResult.digest);
            byte[] plaintextOutput = ReadInputStreamFully(inputStream);

            CollectionAssert.AreEqual(plaintextInput, plaintextOutput);

            DeleteFile(cipherFile);
        }

        [TestMethod]
        public void Test_Attachment_EncryptDecryptEmpty()
        {
            byte[] key = Util.GetSecretBytes(64);
            byte[] plaintextInput = Encoding.UTF8.GetBytes(string.Empty);
            EncryptResult encryptResult = EncryptData(plaintextInput, key);
            string cipherFile = WriteToFile(encryptResult.ciphertext);
            Stream inputStream = AttachmentCipherInputStream.CreateForAttachment(File.Open(cipherFile, FileMode.Open), plaintextInput.Length, key, encryptResult.digest);
            byte[] plaintextOutput = ReadInputStreamFully(inputStream);

            CollectionAssert.AreEqual(plaintextInput, plaintextOutput);

            DeleteFile(cipherFile);
        }

        [TestMethod]
        public void Test_Attachment_DecryptFailOnBadKey()
        {
            string? cipherFile = null;
            bool hitCorrectException = false;

            try
            {
                byte[] key = Util.GetSecretBytes(64);
                byte[] plaintextInput = Encoding.UTF8.GetBytes("Gwen Stacy");
                EncryptResult encryptResult = EncryptData(plaintextInput, key);
                byte[] badKey = new byte[64];

                cipherFile = WriteToFile(encryptResult.ciphertext);

                AttachmentCipherInputStream.CreateForAttachment(File.Open(cipherFile, FileMode.Open), plaintextInput.Length, badKey, encryptResult.digest);
            }
            catch (InvalidMessageException)
            {
                hitCorrectException = true;
            }
            finally
            {
                if (cipherFile != null)
                {
                    DeleteFile(cipherFile);
                }
            }

            Assert.IsTrue(hitCorrectException);
        }

        [TestMethod]
        public void Test_Attachmetn_DecryptFailOnBadDigest()
        {
            string? cipherFile = null;
            bool hitCorrectException = false;

            try
            {
                byte[] key = Util.GetSecretBytes(64);
                byte[] plaintextInput = Encoding.UTF8.GetBytes("Mary Jane Watson");
                EncryptResult encryptResult = EncryptData(plaintextInput, key);
                byte[] badDigest = new byte[32];

                cipherFile = WriteToFile(encryptResult.ciphertext);

                AttachmentCipherInputStream.CreateForAttachment(File.Open(cipherFile, FileMode.Open), plaintextInput.Length, key, badDigest);
            }
            catch (InvalidMessageException)
            {
                hitCorrectException = true;
            }
            finally
            {
                if (cipherFile != null)
                {
                    DeleteFile(cipherFile);
                }
            }

            Assert.IsTrue(hitCorrectException);
        }

        [TestMethod]
        public void Test_Attachment_DecryptFailOnNullDigest()
        {
            string? cipherFile = null;
            bool hitCorrectException = false;

            try
            {
                byte[] key = Util.GetSecretBytes(64);
                byte[] plaintextInput = Encoding.UTF8.GetBytes("Aunt May");
                EncryptResult encryptResult = EncryptData(plaintextInput, key);

                cipherFile = WriteToFile(encryptResult.ciphertext);

                AttachmentCipherInputStream.CreateForAttachment(File.Open(cipherFile, FileMode.Open), plaintextInput.Length, key, null);
            }
            catch (InvalidMessageException)
            {
                hitCorrectException = true;
            }
            finally
            {
                if (cipherFile != null)
                {
                    DeleteFile(cipherFile);
                }
            }

            Assert.IsTrue(hitCorrectException);
        }

        [TestMethod]
        public void Test_Attachment_DecryptFailOnBadMac()
        {
            string? cipherFile = null;
            bool hitCorrectException = false;

            try
            {
                byte[] key = Util.GetSecretBytes(64);
                byte[] plaintextInput = Encoding.UTF8.GetBytes("Uncle Ben");
                EncryptResult encryptResult = EncryptData(plaintextInput, key);
                byte[] badMacCiphertext = new byte[encryptResult.ciphertext.Length];
                Array.Copy(encryptResult.ciphertext, badMacCiphertext, badMacCiphertext.Length);

                badMacCiphertext[badMacCiphertext.Length - 1] = 0;

                cipherFile = WriteToFile(badMacCiphertext);

                AttachmentCipherInputStream.CreateForAttachment(File.Open(cipherFile, FileMode.Open), plaintextInput.Length, key, encryptResult.digest);
            }
            catch (InvalidMessageException)
            {
                hitCorrectException = true;
            }
            finally
            {
                if (cipherFile != null)
                {
                    DeleteFile(cipherFile);
                }
            }

            Assert.IsTrue(hitCorrectException);
        }

        [TestMethod]
        public void Test_Sticker_EncryptDecrypt()
        {
            byte[] packKey = Util.GetSecretBytes(32);
            byte[] plaintextInput = Encoding.UTF8.GetBytes("Peter Parker");
            EncryptResult encryptResult = EncryptData(plaintextInput, ExpandPackKey(packKey));
            Stream inputStream = AttachmentCipherInputStream.CreateForStickerData(encryptResult.ciphertext, packKey);
            byte[] plaintextOutput = ReadInputStreamFully(inputStream);

            CollectionAssert.AreEqual(plaintextInput, plaintextOutput);
        }

        [TestMethod]
        public void Test_Sticker_EncryptDecryptEmpty()
        {
            byte[] packKey = Util.GetSecretBytes(32);
            byte[] plaintextInput = Encoding.UTF8.GetBytes(string.Empty);
            EncryptResult encryptResult = EncryptData(plaintextInput, ExpandPackKey(packKey));
            Stream inputStream = AttachmentCipherInputStream.CreateForStickerData(encryptResult.ciphertext, packKey);
            byte[] plaintextOutput = ReadInputStreamFully(inputStream);

            CollectionAssert.AreEqual(plaintextInput, plaintextOutput);
        }

        [TestMethod]
        public void Test_Sticker_DecryptFailOnBadKey()
        {
            bool hitCorrectException = false;

            try
            {
                byte[] packKey = Util.GetSecretBytes(32);
                byte[] plaintextInput = Encoding.UTF8.GetBytes("Gwen Stacy");
                EncryptResult encryptResult = EncryptData(plaintextInput, ExpandPackKey(packKey));
                byte[] badPackKey = new byte[32];

                AttachmentCipherInputStream.CreateForStickerData(encryptResult.ciphertext, badPackKey);
            }
            catch (InvalidMessageException)
            {
                hitCorrectException = true;
            }

            Assert.IsTrue(hitCorrectException);
        }

        [TestMethod]
        public void Test_Sticker_DecryptFailOnBadMac()
        {
            bool hitCorrectException = false;
            
            try
            {
                byte[] packKey = Util.GetSecretBytes(32);
                byte[] plaintextInput = Encoding.UTF8.GetBytes("Uncle Ben");
                EncryptResult encryptResult = EncryptData(plaintextInput, ExpandPackKey(packKey));
                byte[] badMacCiphertext = new byte[encryptResult.ciphertext.Length];
                Array.Copy(encryptResult.ciphertext, badMacCiphertext, badMacCiphertext.Length);

                badMacCiphertext[badMacCiphertext.Length - 1] = 0;

                AttachmentCipherInputStream.CreateForStickerData(badMacCiphertext, packKey);
            }
            catch (InvalidMessageException)
            {
                hitCorrectException = true;
            }

            Assert.IsTrue(hitCorrectException);
        }

        private static EncryptResult EncryptData(byte[] data, byte[] keyMaterial)
        {
            MemoryStream outputStream = new MemoryStream();
            AttachmentCipherOutputStream encryptStream = new AttachmentCipherOutputStream(keyMaterial, outputStream);

            encryptStream.Write(data, 0, data.Length);
            encryptStream.Flush();
            encryptStream.Dispose();

            return new EncryptResult(outputStream.ToArray(), encryptStream.GetTransmittedDigest());
        }

        private static string WriteToFile(byte[] data)
        {
            string file = Path.GetTempFileName();
            FileStream outputStream = File.OpenWrite(file);

            outputStream.Write(data, 0, data.Length);
            outputStream.Dispose();

            return file;
        }

        private static void DeleteFile(string path)
        {
            if (File.Exists(path))
            {
                try
                {
                    File.Delete(path);
                }
                catch (IOException)
                {
                    // for some reason this fails
                }
            }
        }

        private static byte[] ReadInputStreamFully(Stream inputStream)
        {
            MemoryStream outputStream = new MemoryStream();
            Util.Copy(inputStream, outputStream);
            return outputStream.ToArray();
        }

        private static byte[] ExpandPackKey(byte[] shortKey)
        {
            return new HKDFv3().deriveSecrets(shortKey, Encoding.UTF8.GetBytes("Sticker Pack"), 64);
        }

        private class EncryptResult
        {
            public readonly byte[] ciphertext;
            public readonly byte[] digest;

            public EncryptResult(byte[] ciphertext, byte[] digest)
            {
                this.ciphertext = ciphertext;
                this.digest = digest;
            }
        }
    }
}
