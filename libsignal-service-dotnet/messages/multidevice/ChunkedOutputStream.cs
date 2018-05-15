using System;
using System.IO;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class ChunkedOutputStream
    {
        protected readonly Stream output;

        public ChunkedOutputStream(Stream output)
        {
            this.output = output;
        }

        protected void writeVarint32(int value)// throws IOException
        {
            /*while (true)
            {
                if ((value & ~0x7F) == 0)
                {
                    output.Write(value, 0);
                    return;
                }
                else
                {
                    output.Write((value & 0x7F) | 0x80);
                    value >>= 7;
                }
            }*/
            throw new NotImplementedException();
        }

        protected void writeStream(Stream input)// throws IOException
        {
            /*byte[] buffer = new byte[4096];
            int read;

            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }

            input.close();*/
            throw new NotImplementedException();
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
