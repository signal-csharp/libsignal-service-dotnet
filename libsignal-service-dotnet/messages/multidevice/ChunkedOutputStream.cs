using System;
using System.IO;

namespace libsignalservice.messages.multidevice
{
    public class ChunkedOutputStream
    {
        protected readonly Stream output;

        public ChunkedOutputStream(Stream output)
        {
            this.output = output;
        }

        protected void WriteVarint32(int value)
        {
            // TODO: Test by comparing to Java implementation
            while (true)
            {
                if ((value & ~0x7F) == 0)
                {
                    byte[] valueBytes = BitConverter.GetBytes(value);
                    output.Write(valueBytes, 0, valueBytes.Length);
                    return;
                }
                else
                {
                    byte[] valueBytes = BitConverter.GetBytes((value & 0x7F) | 0x80);
                    output.Write(valueBytes, 0, valueBytes.Length);
                    value = (int)((uint)value >> 7);
                }
            }
        }

        protected void WriteStream(Stream input)
        {
            byte[] buffer = new byte[4096];
            int read;

            while ((read = input.Read(buffer, 0, buffer.Length)) != 0)
            {
                output.Write(buffer, 0, read);
            }

            input.Dispose();
        }
    }
}
