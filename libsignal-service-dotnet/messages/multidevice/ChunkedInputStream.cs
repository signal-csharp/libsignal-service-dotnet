/** 
 * Copyright (C) 2017 smndtrl, golf1052
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

 using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace libsignalservice.messages.multidevice
{
    public class ChunkedInputStream
    {
        protected readonly Stream input;

        public ChunkedInputStream(Stream input)
        {
            this.input = input;
        }

        protected int readRawVarint32()// throws IOException
        {
            byte tmp = (byte)input.ReadByte();
            if (tmp >= 0)
            {
                return tmp;
            }
            int result = tmp & 0x7f;
            if ((tmp = (byte)input.ReadByte()) >= 0)
            {
                result |= tmp << 7;
            }
            else
            {
                result |= (tmp & 0x7f) << 7;
                if ((tmp = (byte)input.ReadByte()) >= 0)
                {
                    result |= tmp << 14;
                }
                else
                {
                    result |= (tmp & 0x7f) << 14;
                    if ((tmp = (byte)input.ReadByte()) >= 0)
                    {
                        result |= tmp << 21;
                    }
                    else
                    {
                        result |= (tmp & 0x7f) << 21;
                        result |= (tmp = (byte)input.ReadByte()) << 28;
                        if (tmp < 0)
                        {
                            // Discard upper 32 bits.
                            for (int i = 0; i < 5; i++)
                            {
                                if ((byte)input.ReadByte() >= 0)
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

        internal class LimitedInputStream : MemoryStream
        {
            private long left;
            private long mark = -1;

            internal LimitedInputStream(long limit) : base()
            {
                left = limit;
            }

            public override long Length
            {
                get
                {
                    return Math.Min(base.Length, left);
                }
            }

            public override int ReadByte()
            {
                if (left == 0)
                {
                    return -1;
                }

                int result = base.ReadByte();
                if (result != -1)
                {
                    --left;
                }
                return result;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (left == 0)
                {
                    return -1;
                }

                count = (int)Math.Min(count, left);
                int result = base.Read(buffer, offset, count);
                if (result != -1)
                {
                    left -= result;
                }
                return result;
            }
        }
    }
}
