using libsignalservice.util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace libsignalservice.crypto
{
    internal class PaddingInputStream : Stream
    {
        private readonly Stream InputStream;
        private long PaddingRemaining;

        public override bool CanRead => throw new NotImplementedException();
        public override bool CanSeek => throw new NotImplementedException();
        public override bool CanWrite => throw new NotImplementedException();
        public override long Length { get => InputStream.Length + Util.ToIntExact(PaddingRemaining); }
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public PaddingInputStream(Stream inputStream, long plainTextLength)
        {
            InputStream = inputStream;
            PaddingRemaining = GetPaddedSize(plainTextLength) - plainTextLength;
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int result = InputStream.Read(buffer, offset, count);
            if (result >= 0)
                return result;

            if (PaddingRemaining > 0)
            {
                count = Math.Min(count, Util.ToIntExact(PaddingRemaining));
                PaddingRemaining -= count;
                return count;
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

        public static long GetPaddedSize(long size)
        {
            return size;
        }

        private static long GetRoundedUp(long size, long interval)
        {
            long multiplier = (long)Math.Ceiling(((double)size) / interval);
            return interval * multiplier;
        }
    }
}
