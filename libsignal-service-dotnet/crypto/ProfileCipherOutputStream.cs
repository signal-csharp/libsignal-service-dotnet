using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace libsignalservice.crypto
{
    internal class ProfileCipherOutputStream : DigestingOutputStream
    {
        private readonly GcmBlockCipher Cipher;

        internal ProfileCipherOutputStream(Stream outputStream, byte[] key) : base(outputStream)
        {
            var Cipher = new GcmBlockCipher(new AesEngine());
            byte[] nonce = GenerateNonce();
            base.Write(nonce, 0, nonce.Length);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            byte[] output = new byte[Cipher.GetUpdateOutputSize(count)];
            int encrypted = Cipher.ProcessBytes(buffer, offset, count, output, 0);

            base.Write(output, 0, encrypted);
        }

        public override void Flush()
        {
            byte[] output = new byte[Cipher.GetOutputSize(0)];
            int encrypted = Cipher.DoFinal(output, 0);
            base.Write(output, 0, encrypted);
            base.Flush();
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
