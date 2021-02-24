using System.IO;
using System.Security.Cryptography;
using libsignalservice.util;

namespace libsignalservice.crypto
{
    public class AttachmentCipherOutputStream : DigestingOutputStream
    {
        private readonly Aes Aes;
        private readonly CryptoStream Cipher;
        private readonly ICryptoTransform Encryptor;
        private readonly MemoryStream TmpStream = new MemoryStream();
        private readonly IncrementalHash Mac;
        
        public AttachmentCipherOutputStream(byte[] combinedKeyMaterial, Stream outputStream) : base(outputStream)
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
            WriteToCipherStream(buffer, offset, count);
            byte[] cipherBuffer = new byte[Aes.BlockSize];
            int read = TmpStream.Read(cipherBuffer, 0, cipherBuffer.Length);
            while (read > 0)
            {
                Mac.AppendData(cipherBuffer, 0, read);
                base.Write(cipherBuffer, 0, read);
                read = TmpStream.Read(cipherBuffer, 0, cipherBuffer.Length);
            }
        }

        public override void Flush()
        {
            FlushFinalBlock();
            byte[] cipherBuffer = new byte[Aes.BlockSize];
            int read = TmpStream.Read(cipherBuffer, 0, cipherBuffer.Length);
            while (read > 0)
            {
                Mac.AppendData(cipherBuffer, 0, read);
                base.Write(cipherBuffer, 0, read);
                read = TmpStream.Read(cipherBuffer, 0, cipherBuffer.Length);
            }
            byte[] auth = Mac.GetHashAndReset();
            base.Write(auth, 0, auth.Length);
            base.Flush();
        }

        private void WriteToCipherStream(byte[] buffer, int offset, int count)
        {
            var oldPos = TmpStream.Position;
            Cipher.Write(buffer, offset, count);
            TmpStream.Position = oldPos;
        }

        private void FlushFinalBlock()
        {
            var oldPos = TmpStream.Position;
            Cipher.FlushFinalBlock();
            TmpStream.Position = oldPos;
        }
    }
}
