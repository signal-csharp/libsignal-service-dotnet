using System;
using System.IO;
using libsignalservice.util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace libsignalservice.crypto
{
    public class ProfileCipherInputStream : Stream
    {
        private readonly GcmBlockCipher cipher;
        private readonly Stream inputStream;

        private bool finished = false;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotImplementedException();
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }


        public ProfileCipherInputStream(Stream inputStream, byte[] key)
        {
            cipher = new GcmBlockCipher(new AesEngine());
            byte[] nonce = new byte[12];
            Util.ReadFully(inputStream, nonce);
            cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce));
            this.inputStream = inputStream;
        }

        protected override void Dispose(bool disposing)
        {
            inputStream.Dispose();
            base.Dispose(disposing);
        }

        public override void Flush()
        {
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (finished) return 0;
            try
            {
                byte[] ciphertext = new byte[count / 2];
                int read = inputStream.Read(ciphertext, 0, ciphertext.Length);

                if (read <= 0)
                {
                    if (cipher.GetOutputSize(0) > count)
                    {
                        throw new InvalidOperationException("Need: " + cipher.GetOutputSize(0) + " but only have: " + count);
                    }
                    finished = true;
                    return cipher.DoFinal(buffer, offset);
                }
                else
                {
                    if (cipher.GetUpdateOutputSize(read) > count)
                    {
                        throw new InvalidOperationException("Need: " + cipher.GetOutputSize(read) + " but only have: " + count);
                    }
                    return cipher.ProcessBytes(ciphertext, 0, read, buffer, offset);
                }
            }
            catch (InvalidCipherTextException e)
            {
                throw new IOException(null, e);
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
