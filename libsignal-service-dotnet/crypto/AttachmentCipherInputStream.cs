using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using libsignal;
using libsignal.kdf;
using libsignalservice.util;
using TextSecure.libsignal;

namespace libsignalservice.crypto
{
    public class AttachmentCipherInputStream : Stream
    {
        private static readonly int BLOCK_SIZE = 16;
        private static readonly int CIPHER_KEY_SIZE = 32;
        private static readonly int MAC_KEY_SIZE = 32;

        private readonly Stream inputStream;
        private readonly Aes aes;
        private readonly CryptoStream cipher;
        private readonly ICryptoTransform decryptor;

        private readonly long totalDataSize;
        private long totalRead = 0;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => totalDataSize;
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputStream"></param>
        /// <param name="plaintextLength"></param>
        /// <param name="combinedKeyMaterial"></param>
        /// <param name="digest"></param>
        /// <returns></returns>
        /// <exception cref="InvalidMessageException"></exception>
        public static Stream CreateForAttachment(Stream inputStream, long plaintextLength, byte[] combinedKeyMaterial, byte[]? digest)
        {
            try
            {
                byte[][] parts = Util.Split(combinedKeyMaterial, CIPHER_KEY_SIZE, MAC_KEY_SIZE);
                IncrementalHash mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, parts[1]);
                const int MacLength = 32;

                if (inputStream.Length <= BLOCK_SIZE + MacLength)
                {
                    throw new InvalidMessageException("Message shorter than crypto overhead!");
                }

                if (digest == null)
                {
                    throw new InvalidMacException("Missing digest");
                }

                VerifyMac(inputStream, inputStream.Length, mac, digest);
                inputStream.Seek(0, SeekOrigin.Begin);
                // We need to truncate the MAC off the end of the input stream or CryptoStream will fail to decrypt
                // correctly because it will think there's more data to decrypt when the MAC isn't actually part of
                // what needs to be decrypted.
                inputStream.SetLength(inputStream.Length - MacLength);

                Stream stream = new AttachmentCipherInputStream(inputStream, parts[0], inputStream.Length - BLOCK_SIZE);

                if (plaintextLength > 0)
                {
                    stream = new ContentLengthInputStream(stream, plaintextLength);
                }

                return stream;
            }
            catch (InvalidMacException ex)
            {
                throw new InvalidMessageException(ex);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <param name="packKey"></param>
        /// <returns></returns>
        /// <exception cref="InvalidMessageException"></exception>
        public static Stream CreateForStickerData(byte[] data, byte[] packKey)
        {
            try
            {
                byte[] combinedKeyMaterial = new HKDFv3().deriveSecrets(packKey, Encoding.UTF8.GetBytes("Sticker Pack"), 64);
                byte[][] parts = Util.Split(combinedKeyMaterial, CIPHER_KEY_SIZE, MAC_KEY_SIZE);
                IncrementalHash mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, parts[1]);
                const int MacLength = 32;

                if (data.Length <= BLOCK_SIZE + MacLength)
                {
                    throw new InvalidMessageException("Message shorter than crypto overhead!");
                }

                MemoryStream inputStream = new MemoryStream(data);
                VerifyMac(inputStream, data.Length, mac, null);
                inputStream.Seek(0, SeekOrigin.Begin);
                // We need to truncate the MAC off the end of the input stream or CryptoStream will fail to decrypt
                // correctly because it will think there's more data to decrypt when the MAC isn't actually part of
                // what needs to be decrypted.
                inputStream.SetLength(inputStream.Length - MacLength);

                return new AttachmentCipherInputStream(inputStream, parts[0], data.Length - BLOCK_SIZE);
            }
            catch (InvalidMacException ex)
            {
                throw new InvalidMessageException(ex);
            }
        }

        private AttachmentCipherInputStream(Stream inputStream, byte[] key, long totalDataSize)
        {
            this.inputStream = inputStream;

            byte[] iv = new byte[BLOCK_SIZE];
            ReadFully(iv);

            aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            decryptor = aes.CreateDecryptor();
            cipher = new CryptoStream(this.inputStream, decryptor, CryptoStreamMode.Read);

            totalRead = 0;
            this.totalDataSize = totalDataSize;
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (totalRead < totalDataSize)
            {
                int read = cipher.Read(buffer, offset, (int)Math.Min(count, totalDataSize - totalRead));
                totalRead += read;
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

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputStream"></param>
        /// <param name="length"></param>
        /// <param name="mac"></param>
        /// <param name="theirDigest"></param>
        /// <exception cref="InvalidMacException"></exception>
        private static void VerifyMac(Stream inputStream, long length, IncrementalHash mac, byte[]? theirDigest)
        {
            IncrementalHash digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            const int MacLength = 32;
            int remainingData = Util.ToIntExact(length) - MacLength;
            byte[] buffer = new byte[4096];

            while (remainingData > 0)
            {
                int read = inputStream.Read(buffer, 0, Math.Min(buffer.Length, remainingData));
                mac.AppendData(buffer, 0, read);
                digest.AppendData(buffer, 0, read);
                remainingData -= read;
            }

            byte[] ourMac = mac.GetHashAndReset();
            byte[] theirMac = new byte[MacLength];
            Util.ReadFully(inputStream, theirMac);

            if (!ourMac.SequenceEqual(theirMac))
            {
                throw new InvalidMacException("MAC doesn't match!");
            }

            digest.AppendData(theirMac, 0, theirMac.Length);
            byte[] ourDigest = digest.GetHashAndReset();

            if (theirDigest != null && !ourDigest.SequenceEqual(theirDigest))
            {
                throw new InvalidMacException("Digest doesn't match!");
            }
        }

        private void ReadFully(byte[] buffer)
        {
            int offset = 0;

            for (;;)
            {
                int read = inputStream.Read(buffer, offset, buffer.Length - offset);

                if (read + offset<buffer.Length)
                    offset += read;
                else
                    return;
            }
        }

        public static long GetCiphertextLength(long plaintextLength)
        {
            return 16 + (((plaintextLength / 16) + 1) * 16) + 32;
        }
    }
}
