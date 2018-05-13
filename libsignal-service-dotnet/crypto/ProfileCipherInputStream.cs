using libsignalservice.util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace libsignalservice.crypto
{
    internal class ProfileCipherInputStream : Stream
    {
        private readonly GcmBlockCipher Cipher;
        private readonly Stream InputStream;
        private bool Finished = false;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotImplementedException();
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }


        public ProfileCipherInputStream(Stream inputStream, byte[] key)
        {
            Cipher = new GcmBlockCipher(new AesEngine());
            byte[] nonce = new byte[12];
            Util.ReadFully(inputStream, nonce);
            Cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce));
            InputStream = inputStream;
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (Finished) return 0;
            try
            {
                byte[] ciphertext = new byte[count / 2];
                int read = InputStream.Read(ciphertext, 0, ciphertext.Length);

                if (read <= 0)
                {
                    if (Cipher.GetOutputSize(0) > count)
                    {
                        throw new InvalidOperationException("Need: " + Cipher.GetOutputSize(0) + " but only have: " + count);
                    }
                    Finished = true;
                    return Cipher.DoFinal(buffer, offset);
                }
                else
                {
                    if (Cipher.GetUpdateOutputSize(read) > count)
                    {
                        throw new InvalidOperationException("Need: " + Cipher.GetOutputSize(read) + " but only have: " + count);
                    }
                    return Cipher.ProcessBytes(ciphertext, 0, read, buffer, offset);
                }
            }
            catch (InvalidCipherTextException e)
            {
                throw new IOException(e.Message);
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}
