using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace libsignalservice.crypto
{
    internal class ProfileCipher
    {
        internal static readonly int NAME_PADDED_LENGTH = 26;
        private readonly byte[] Key;

        internal ProfileCipher(byte[] key)
        {
            Key = key;
        }

        internal byte[] EncryptName(byte[] input, int paddedLength)
        {
            byte[] inputPadded = new byte[paddedLength];

            if (input.Length > inputPadded.Length)
            {
                throw new ArgumentException("Input is too long");
            }

            Array.Copy(input, 0, inputPadded, 0, input.Length);

            using (MemoryStream stream = new MemoryStream())
            {
                using (ProfileCipherOutputStream profileCipherOutputStream = new ProfileCipherOutputStream(stream, Key))
                {
                    profileCipherOutputStream.Write(inputPadded, 0, inputPadded.Length);
                    profileCipherOutputStream.Flush();
                    return stream.ToArray();
                }
            }
        }

        internal byte[] DecryptName(byte[] input)
        {
            using (MemoryStream bais = new MemoryStream(input))
            {
                using (var profileStream = new ProfileCipherInputStream(bais, Key))
                {
                    using (MemoryStream result = new MemoryStream())
                    {
                        byte[] buffer = new byte[4096];
                        int read = 0;

                        while ((read = profileStream.Read(buffer, 0, buffer.Length)) != -1)
                        {
                            result.Write(buffer, 0, read);
                        }
                        return result.ToArray();
                    }
                }
            }
        }
    }
}
