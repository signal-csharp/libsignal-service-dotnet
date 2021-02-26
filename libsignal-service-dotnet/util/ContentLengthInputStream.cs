using System;
using System.IO;

namespace libsignalservice.util
{
    internal class ContentLengthInputStream : Stream
    {
        private readonly Stream inputStream;
        private long bytesRemaining;
        private readonly long totalDataSize;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => totalDataSize;
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public ContentLengthInputStream(Stream inputStream, long contentLength)
        {
            this.inputStream = inputStream;
            totalDataSize = bytesRemaining = contentLength;
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
            if (bytesRemaining == 0)
                return 0;
            int read = inputStream.Read(buffer, offset, Math.Min(count, Util.ToIntExact(bytesRemaining)));
            bytesRemaining -= read;
            return read;
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
