using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace libsignalservice.util
{
    internal class ContentLengthInputStream : Stream
    {
        private readonly Stream InputStream;
        private long BytesRemaining;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotImplementedException();
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public ContentLengthInputStream(Stream inputStream, long contentLength)
        {
            InputStream = inputStream;
            BytesRemaining = contentLength;
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (BytesRemaining == 0)
                return 0;
            int read = InputStream.Read(buffer, offset, Math.Min(count, Util.ToIntExact(BytesRemaining)));
            BytesRemaining -= read;
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
