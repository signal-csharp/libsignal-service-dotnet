using System;
using System.IO;
using libsignalservice.util;

namespace libsignalservice.crypto
{
    internal class PaddingInputStream : Stream
    {
        private readonly Stream inputStream;
        private readonly long plainTextLength;
        private long paddingRemaining;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length { get => GetPaddedSize(plainTextLength); }
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public PaddingInputStream(Stream inputStream, long plainTextLength)
        {
            this.inputStream = inputStream;
            this.plainTextLength = plainTextLength;
            paddingRemaining = GetPaddedSize(plainTextLength) - plainTextLength;
        }

        protected override void Dispose(bool disposing)
        {
            inputStream.Dispose();
            base.Dispose(disposing);
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int result = inputStream.Read(buffer, offset, count);
            if (result > 0)
                return result;

            if (paddingRemaining > 0)
            {
                count = Math.Min(count, Util.ToIntExact(paddingRemaining));
                paddingRemaining -= count;
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
            return (int)Math.Max(541, Math.Floor(Math.Pow(1.05, Math.Ceiling(Math.Log(size) / Math.Log(1.05)))));
        }
    }
}
