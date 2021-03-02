using System;
using System.IO;

namespace libsignalservice.messages.multidevice
{
    public class ChunkedInputStream
    {
        protected readonly Stream inputStream;

        public ChunkedInputStream(Stream input)
        {
            inputStream = input;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public int ReadRawVarint32()
        {
            int tmpInt = inputStream.ReadByte();
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
            if ((tmp = (sbyte)inputStream.ReadByte()) >= 0)
            {
                result |= tmp << 7;
            }
            else
            {
                result |= (tmp & 0x7f) << 7;
                if ((tmp = (sbyte)inputStream.ReadByte()) >= 0)
                {
                    result |= tmp << 14;
                }
                else
                {
                    result |= (tmp & 0x7f) << 14;
                    if ((tmp = (sbyte)inputStream.ReadByte()) >= 0)
                    {
                        result |= tmp << 21;
                    }
                    else
                    {
                        result |= (tmp & 0x7f) << 21;
                        result |= (tmp = (sbyte)inputStream.ReadByte()) << 28;
                        if (tmp < 0)
                        {
                            // Discard upper 32 bits.
                            for (int i = 0; i < 5; i++)
                            {
                                if ((sbyte)inputStream.ReadByte() >= 0)
                                {
                                    return result;
                                }
                            }

                            throw new IOException("Malformed variant!");
                        }
                    }
                }
            }

            return result;
        }

        internal class LimitedInputStream : Stream
        {
            private Stream inputStream;
            private long left;

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotImplementedException();
            public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

            internal LimitedInputStream(Stream inputStream, long limit)
            {
                this.inputStream = inputStream;
                left = limit;
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
                if (left == 0)
                    return 0;

                count = (int) Math.Min(count, left);
                int result = inputStream.Read(buffer, offset, count);
                if (result > 0)
                    left -= result;
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
