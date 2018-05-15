using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace libsignalservice.crypto
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class DigestingOutputStream : Stream
    {
        private IncrementalHash RunningDigest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private Stream OutputStream { get; }
        public override bool CanRead => throw new NotImplementedException();
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotImplementedException();
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public DigestingOutputStream(Stream outputStream)
        {
            OutputStream = outputStream;
        }

        public override void Flush()
        {
            OutputStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
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
            RunningDigest.AppendData(buffer, offset, count);
            OutputStream.Write(buffer, offset, count);
        }

        public byte[] GetTransmittedDigest()
        {
            return RunningDigest.GetHashAndReset();
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
