using System;
using System.IO;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class ChunkedInputStream
    {
        protected readonly Stream InputStream;

        public ChunkedInputStream(Stream input)
        {
            InputStream = input;
        }

        public int ReadRawVarint32()// throws IOException
        {
            int tmpInt = InputStream.ReadByte();
            if (tmpInt == -1)
            {
                return -1;
            }
            sbyte tmp = (sbyte) tmpInt;
            if (tmp >= 0)
            {
                return tmp;
            }
            int result = tmp & 0x7f;
            if ((tmp = (sbyte)InputStream.ReadByte()) >= 0)
            {
                result |= tmp << 7;
            }
            else
            {
                result |= (tmp & 0x7f) << 7;
                if ((tmp = (sbyte)InputStream.ReadByte()) >= 0)
                {
                    result |= tmp << 14;
                }
                else
                {
                    result |= (tmp & 0x7f) << 14;
                    if ((tmp = (sbyte)InputStream.ReadByte()) >= 0)
                    {
                        result |= tmp << 21;
                    }
                    else
                    {
                        result |= (tmp & 0x7f) << 21;
                        result |= (tmp = (sbyte)InputStream.ReadByte()) << 28;
                        if (tmp < 0)
                        {
                            // Discard upper 32 bits.
                            for (int i = 0; i < 5; i++)
                            {
                                if ((sbyte)InputStream.ReadByte() >= 0)
                                {
                                    return result;
                                }
                            }

                            throw new IOException("Malformed varint!");
                        }
                    }
                }
            }

            return result;
        }

        internal class LimitedInputStream : Stream
        {
            private Stream InputStream;
            private long Left;

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotImplementedException();
            public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

            internal LimitedInputStream(Stream inputStream, long limit)
            {
                InputStream = inputStream;
                Left = limit;
            }

            public override void Flush()
            {
                throw new NotImplementedException();
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (Left == 0)
                    return 0;

                count = (int) Math.Min(count, Left);
                int result = InputStream.Read(buffer, offset, count);
                if (result > 0)
                    Left -= result;
                return result;
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
}
