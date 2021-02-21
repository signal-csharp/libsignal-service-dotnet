using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using libsignal.util;
using libsignalservice.util;
using libsignalservicedotnet.crypto;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace libsignalservice.crypto
{
    public class ProfileCipher
    {
        internal static readonly int NAME_PADDED_LENGTH = 26;
        private readonly byte[] key;

        public ProfileCipher(byte[] key)
        {
            this.key = key;
        }

        public byte[] EncryptName(byte[] input, int paddedLength)
        {
            try
            {
                byte[] inputPadded = new byte[paddedLength];

                if (input.Length > inputPadded.Length)
                {
                    throw new ArgumentException($"Input is too long: {Encoding.UTF8.GetString(input)}");
                }

                Array.Copy(input, 0, inputPadded, 0, input.Length);

                byte[] nonce = Util.GetSecretBytes(12);

                GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
                cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce));

                byte[] ciphertext = new byte[cipher.GetUpdateOutputSize(inputPadded.Length)];
                cipher.ProcessBytes(inputPadded, 0, inputPadded.Length, ciphertext, 0);

                byte[] tag = new byte[cipher.GetOutputSize(0)];
                cipher.DoFinal(tag, 0);

                return ByteUtil.combine(nonce, ciphertext, tag);
            }
            catch (InvalidCipherTextException ex)
            {
                throw new ArgumentException(null, ex);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        /// <exception cref="InvalidCiphertextException"></exception>
        public byte[] DecryptName(byte[] input)
        {
            try
            {
                if (input.Length < 12 + 16 + 1)
                {
                    throw new InvalidCipherTextException($"Too short: {input.Length}");
                }

                byte[] nonce = new byte[12];
                Array.Copy(input, 0, nonce, 0, nonce.Length);

                GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
                cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce));

                byte[] paddedPlaintextOne = new byte[cipher.GetUpdateOutputSize(input.Length - 12)];
                cipher.ProcessBytes(input, 12, input.Length - 12, paddedPlaintextOne, 0);

                byte[] paddedPlaintextTwo = new byte[cipher.GetOutputSize(0)];
                cipher.DoFinal(paddedPlaintextTwo, 0);

                byte[] paddedPlaintext = ByteUtil.combine(paddedPlaintextOne, paddedPlaintextTwo);
                int plaintextLength = 0;

                for (int i = paddedPlaintext.Length - 1; i >= 0; i--)
                {
                    if (paddedPlaintext[i] != 0x00)
                    {
                        plaintextLength = i + 1;
                        break;
                    }
                }

                byte[] plaintext = new byte[plaintextLength];
                Array.Copy(paddedPlaintext, 0, plaintext, 0, plaintextLength);

                return plaintext;
            }
            catch (InvalidCipherTextException ex)
            {
                throw new InvalidCiphertextException(ex);
            }
        }

        public bool VerifyUnidentifiedAccess(byte[] theirUnidentifiedAccessVerifier)
        {
            try
            {
                if (theirUnidentifiedAccessVerifier == null || theirUnidentifiedAccessVerifier.Length == 0) return false;

                byte[] unidentifiedAccessKey = UnidentifiedAccess.DeriveAccessKeyFrom(key);

                HMAC mac = new HMACSHA256(unidentifiedAccessKey);

                byte[] ourUnidentifiedAccessVerifier = mac.ComputeHash(new byte[32]);

                return Enumerable.SequenceEqual(theirUnidentifiedAccessVerifier, ourUnidentifiedAccessVerifier);
            }
            catch (InvalidKeyException ex)
            {
                throw new ArgumentException(null, ex);
            }
        }
    }
}
