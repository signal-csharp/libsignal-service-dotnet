using libsignalservice.util;
using Org.BouncyCastle.Crypto.Modes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace libsignalservice.crypto
{
    internal class AttachmentCipherOutputStream : DigestingOutputStream
    {
        private readonly Aes Aes;
        private readonly CryptoStream Cipher;
        private readonly ICryptoTransform Encryptor;
        private readonly MemoryStream TmpStream = new MemoryStream();
        private readonly IncrementalHash Mac;
        
        internal AttachmentCipherOutputStream(byte[] combinedKeyMaterial, Stream outputStream) : base(outputStream)
        {
            byte[][] keyParts = Util.Split(combinedKeyMaterial, 32, 32);
            Aes = Aes.Create();
            Aes.Key = keyParts[0];
            Aes.Mode = CipherMode.CBC;
            Aes.Padding = PaddingMode.PKCS7;
            Encryptor = Aes.CreateEncryptor();
            Cipher = new CryptoStream(TmpStream, Encryptor, CryptoStreamMode.Write);
            Mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, keyParts[1]);
            Mac.AppendData(Aes.IV);
            base.Write(Aes.IV, 0, Aes.IV.Length);
        }

        internal static long GetCiphertextLength(long plaintextLength)
        {
            return 16 + (((plaintextLength / 16) + 1) * 16) + 32;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Cipher.Write(buffer, offset, count);
            byte[] cipherBuffer = new byte[Aes.BlockSize];
            int read = TmpStream.Read(cipherBuffer, 0, cipherBuffer.Length);
            while (read > 0)
            {
                Mac.AppendData(buffer);
                base.Write(cipherBuffer, 0, read);
            }
        }

        public override void Flush()
        {
            Cipher.FlushFinalBlock();
            byte[] cipherBuffer = new byte[Aes.BlockSize];
            int read = TmpStream.Read(cipherBuffer, 0, cipherBuffer.Length);
            while (read > 0)
            {
                Mac.AppendData(cipherBuffer, 0, read);
                base.Write(cipherBuffer, 0, read);
            }
            byte[] auth = Mac.GetHashAndReset();
            base.Write(auth, 0, auth.Length);
            base.Flush();
        }

        public static void ReadIntoBuffer(Stream s)
        {

        }
    }
}
