using libsignal;
using libsignalservice.util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace libsignalservice.crypto
{
    public class AttachmentCipherInputStream : Stream
    {
        private static readonly int BLOCK_SIZE = 16;
        private static readonly int CIPHER_KEY_SIZE = 32;
        private static readonly int MAC_KEY_SIZE = 32;

        private readonly Stream InputStream;
        private readonly Aes Aes;
        private readonly CryptoStream Cipher;
        private readonly ICryptoTransform Decryptor;
        private readonly MemoryStream TmpStream = new MemoryStream();
        private long TotalDataSize;
        private long TotalRead = 0;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotImplementedException();
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public AttachmentCipherInputStream(Stream inputStream, byte[] combinedKeyMaterial, byte[] digest)
        {
            InputStream = inputStream;
            long fileSize = inputStream.Length;
            byte[][] keyParts = Util.Split(combinedKeyMaterial, 32, 32);
            IncrementalHash mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, keyParts[1]);


            if (InputStream.Length <= BLOCK_SIZE + 32)
            {
                throw new InvalidMessageException("Message shorter than crypto overhead!");
            }

            VerifyMac(InputStream, mac, digest);
            InputStream.Seek(0, SeekOrigin.Begin);

            byte[] iv = new byte[BLOCK_SIZE];
            ReadFully(iv);
            Aes = Aes.Create();
            Aes.Key = keyParts[0];
            Aes.IV = iv;
            Aes.Mode = CipherMode.CBC;
            Aes.Padding = PaddingMode.PKCS7;
            Decryptor = Aes.CreateDecryptor();
            Cipher = new CryptoStream(InputStream, Decryptor, CryptoStreamMode.Read);
            
            TotalDataSize = fileSize - Aes.BlockSize - 32;
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (TotalRead < TotalDataSize)
            {
                int read = Cipher.Read(buffer, offset, (int)Math.Min(count, TotalDataSize - TotalRead));
                TotalRead += read;
                return read;
            }
            return 0;
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

        private void VerifyMac(Stream fin, IncrementalHash mac, byte[] theirDigest)
        {
            IncrementalHash digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            int remainingData = Util.ToIntExact(fin.Length) - 32;
            byte[] buffer = new byte[4096];

            while (remainingData > 0)
            {
                int read = fin.Read(buffer, 0, Math.Min(buffer.Length, remainingData));
                mac.AppendData(buffer, 0, read);
                digest.AppendData(buffer, 0, read);
                remainingData -= read;
            }

            byte[] ourMac = mac.GetHashAndReset();
            byte[] theirMac = new byte[32];
            Util.ReadFully(fin, theirMac);

            if (!ourMac.SequenceEqual(theirMac))
            {
                throw new Exception("MAC doesn't match!"); //TODO InvalidMacException
            }

            digest.AppendData(theirMac, 0, theirMac.Length);
            byte[] ourDigest = digest.GetHashAndReset();

            if (theirDigest != null && !ourDigest.SequenceEqual(theirDigest))
            {
                throw new Exception("Digest doesn't match!"); //TODO InvalidMacException
            }
        }

        private void ReadFully(byte[] buffer)
        {
            int offset = 0;

            for (;;)
            {
                int read = InputStream.Read(buffer, offset, buffer.Length - offset);

                if (read + offset<buffer.Length)
                    offset += read;
                else
                    return;
            }
        }
    }
}
