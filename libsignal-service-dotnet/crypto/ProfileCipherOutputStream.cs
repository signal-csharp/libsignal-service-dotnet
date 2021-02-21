using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace libsignalservice.crypto
{
    public class ProfileCipherOutputStream : DigestingOutputStream
    {
        private readonly GcmBlockCipher cipher;

        public ProfileCipherOutputStream(Stream outputStream, byte[] key) : base(outputStream)
        {
            cipher = new GcmBlockCipher(new AesEngine());

            byte[] nonce = GenerateNonce();
            cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce));

            base.Write(nonce, 0, nonce.Length);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            byte[] output = new byte[cipher.GetUpdateOutputSize(count)];
            int encrypted = cipher.ProcessBytes(buffer, offset, count, output, 0);

            base.Write(output, 0, encrypted);
        }

        public override void WriteByte(byte b)
        {
            byte[] output = new byte[cipher.GetUpdateOutputSize(1)];
            int encrypted = cipher.ProcessByte(b, output, 0);

            base.Write(output, 0, encrypted);
        }

        public override void Flush()
        {
            try
            {
                byte[] output = new byte[cipher.GetOutputSize(0)];
                int encrypted = cipher.DoFinal(output, 0);
                base.Write(output, 0, encrypted);
                base.Flush();
            }
            catch (InvalidCipherTextException ex)
            {
                throw new ArgumentException(null, ex);
            }
            
        }

        private byte[] GenerateNonce()
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] secret = new byte[12];
                rng.GetBytes(secret);
                return secret;
            }
        }

        public static long GetCiphertextLength(long plaintextLength)
        {
            return 12 + 16 + plaintextLength;
        }
    }
}
