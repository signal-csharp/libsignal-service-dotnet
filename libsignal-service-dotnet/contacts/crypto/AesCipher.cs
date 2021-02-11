using System;
using libsignal.util;
using libsignalservice.util;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace libsignalservice.contacts.crypto
{
    internal static class AesCipher
    {
        private const int TAG_LENGTH_BYTES = 16;
        private const int TAG_LENGTH_BITS = TAG_LENGTH_BYTES * 8;

        internal static byte[] Decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] tag)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(false, new AeadParameters(new KeyParameter(key), TAG_LENGTH_BITS, iv));

            byte[] combined = ByteUtil.combine(ciphertext, tag);
            byte[] cipherTextOne = new byte[cipher.GetUpdateOutputSize(combined.Length)];
            cipher.ProcessBytes(combined, 0, combined.Length, cipherTextOne, 0);

            byte[] cipherTextTwo = new byte[cipher.GetOutputSize(0)];
            cipher.DoFinal(cipherTextTwo, 0);
            return ByteUtil.combine(cipherTextOne, cipherTextTwo);
        }

        internal static AesEncryptedResult Encrypt(byte[] key, byte[]? aad, byte[] requestData)
        {
            try
            {
                byte[] iv = Util.GetSecretBytes(12);
                var cipher = new GcmBlockCipher(new AesEngine());
                cipher.Init(true, new AeadParameters(new KeyParameter(key), TAG_LENGTH_BITS, iv));
                if (aad != null)
                {
                    cipher.ProcessAadBytes(aad, 0, aad.Length);
                }

                byte[] cipherText1 = new byte[cipher.GetUpdateOutputSize(requestData.Length)];
                cipher.ProcessBytes(requestData, 0, requestData.Length, cipherText1, 0);

                byte[] cipherText2 = new byte[cipher.GetOutputSize(0)];
                cipher.DoFinal(cipherText2, 0);

                byte[] cipherText = ByteUtil.combine(cipherText1, cipherText2);
                byte[][] parts = ByteUtil.split(cipherText, cipherText.Length - TAG_LENGTH_BYTES, TAG_LENGTH_BYTES);

                return new AesEncryptedResult(iv, parts[0], parts[1], aad);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(null, ex);
            }
        }

        internal class AesEncryptedResult
        {
            public readonly byte[] iv;
            public readonly byte[] data;
            public readonly byte[] mac;
            public readonly byte[]? aad;

            public AesEncryptedResult(byte[] iv, byte[] data, byte[] mac, byte[]? aad)
            {
                this.iv = iv;
                this.data = data;
                this.mac = mac;
                this.aad = aad;
            }
        }
    }
}
