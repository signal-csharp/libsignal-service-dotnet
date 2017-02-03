/** 
 * Copyright (C) 2015-2017 smndtrl, golf1052
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
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace libsignalservice.util
{
    public class Util
    {

        public static byte[] join(params byte[][] input)
        {
            try
            {
                MemoryStream stream = new MemoryStream();
                //ByteArrayOutputStream baos = new ByteArrayOutputStream();
                foreach (byte[] part in input)
                {
                    stream.Write(part, 0, part.Length);
                }

                return stream.ToArray();
            }
            catch (IOException e)
            {
                throw new Exception(e.Message);
            }
        }

        public static byte[][] split(byte[] input, int firstLength, int secondLength)
        {
            byte[][] parts = new byte[2][];

            parts[0] = new byte[firstLength];
            System.Buffer.BlockCopy(input, 0, parts[0], 0, firstLength);

            parts[1] = new byte[secondLength];
            System.Buffer.BlockCopy(input, firstLength, parts[1], 0, secondLength);

            return parts;
        }

        public static byte[] trim(byte[] input, int length)
        {
            byte[] result = new byte[length];
            System.Buffer.BlockCopy(input, 0, result, 0, result.Length);

            return result;
        }

        public static bool isEmpty(String value)
        {
            return value == null || value.Trim().Length == 0;
        }

        public static byte[] getSecretBytes(uint size)
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] secret = new byte[size];
                rng.GetBytes(secret);
                return secret;
            }
        }

        public static uint generateRandomNumber()
        {
            byte[] b = getSecretBytes(sizeof(uint));
            return BitConverter.ToUInt32(b, 0);
        }

        public static void readFully(Stream input, byte[] buffer)
        {
            int offset = 0;

            for (;;)
            {
                int read = input.Read(buffer, offset, buffer.Length - offset);

                if (read + offset < buffer.Length)
                {
                    offset += read;
                }
                else
                {
                    return;
                }
            }
        }

        public static void copy(Stream input, Stream output)
        {
            byte[] buffer = new byte[4096];
            int read;

            while ((read = input.Read(buffer, 0, buffer.Length)) != -1)
            {
                output.Write(buffer, 0, read);
            }

            input.Dispose();
            output.Dispose();
        }

        /*
        public static String readFully(InputStream in)// throws IOException
        {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;

            while ((read = in.read(buffer)) != -1) {
                bout.write(buffer, 0, read);
            }

    in.close();

            return new String(bout.toByteArray());
        }

        public static void readFully(InputStream in, byte[] buffer)// throws IOException
        {
            int offset = 0;

            for (; ;)
            {
                int read = in.read(buffer, offset, buffer.length - offset);

                if (read + offset < buffer.length) offset += read;
                else return;
            }
        }


        public static void copy(InputStream in, OutputStream out)// throws IOException
        {
            byte[] buffer = new byte[4096];
            int read;

            while ((read = in.read(buffer)) != -1) {
      out.write(buffer, 0, read);
            }

    in.close();
    out.close();
        }

        public static void sleep(long millis)
        {
            try
            {
                Thread.sleep(millis);
            }
            catch (InterruptedException e)
            {
                throw new AssertionError(e);
            }
        }*/

        public static void wait(Object locki, ulong millis)
        {
            /*try
            {
                locki.wait(millis);
            }
            catch (InterruptedException e)
            {
                throw new Exception(e);
            }*/
        }

        public static int toIntExact(long value)
        {
            if ((int)value != value)
            {
                throw new ArithmeticException("integer overflow");
            }
            return (int)value;
        }

        internal static byte[] trim(object p, int v)
        {
            throw new NotImplementedException();
        }

        public static byte[] toVarint64(long value)
        {
            MemoryStream output = new MemoryStream();
            throw new NotImplementedException();
            /*while (true)
            {
                if ((value & ~0x7FL) == 0)
                {
                    output.Write((int)value, 0, 1);
                    return output.ToArray();
                }
                else
                {
                    output.Write(((int)value & 0x7F) | 0x80, 0, 1);
                    value >>= 7;
                }
            }*/
        }

        public static long CurrentTimeMillis()
        {
            return (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Ticks / TimeSpan.TicksPerMillisecond;
        }
    }
}
