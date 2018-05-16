using System;
using System.IO;
using System.Security.Cryptography;

namespace libsignalservice.util
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class Util
    {
        public static byte[] Join(params byte[][] input)
        {
            try
            {
                MemoryStream stream = new MemoryStream();
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

        public static byte[][] Split(byte[] input, int firstLength, int secondLength)
        {
            byte[][] parts = new byte[2][];

            parts[0] = new byte[firstLength];
            System.Buffer.BlockCopy(input, 0, parts[0], 0, firstLength);

            parts[1] = new byte[secondLength];
            System.Buffer.BlockCopy(input, firstLength, parts[1], 0, secondLength);

            return parts;
        }

        public static byte[] Trim(byte[] input, int length)
        {
            byte[] result = new byte[length];
            System.Buffer.BlockCopy(input, 0, result, 0, result.Length);

            return result;
        }

        public static bool IsEmpty(String value)
        {
            return value == null || value.Trim().Length == 0;
        }

        public static byte[] GetSecretBytes(uint size)
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
            byte[] b = GetSecretBytes(sizeof(uint));
            return BitConverter.ToUInt32(b, 0);
        }

        /// <summary>
        /// Generates a secure random int with the given number of bits
        /// </summary>
        /// <param name="numBits">Number of bits</param>
        /// <returns>A secure random int</returns>
        /// <remarks>From http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/file/73d5bcd0585d/src/share/classes/java/security/SecureRandom.java#l486</remarks>
        private static int Next(int numBits)
        {
            int numBytes = (numBits + 7) / 8;
            byte[] b = GetSecretBytes((uint)numBytes);
            int next = 0;

            for (int i = 0; i < numBytes; i++)
            {
                next = (next << 8) + (b[i] & 255);
            }

            return (int)((uint)next >> (numBytes * 8 - numBits));
        }

        /// <summary>
        /// Generates a secure random int between 0 and the specified value (exclusive).
        /// </summary>
        /// <param name="bound">The max value (exclusive)</param>
        /// <returns>A secure random int</returns>
        /// <remarks>From http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/file/73d5bcd0585d/src/share/classes/java/util/Random.java#l342</remarks>
        private static int NextInt(int bound)
        {
            if (bound <= 0)
            {
                throw new ArgumentException("bound must be positive");
            }

            if ((bound & bound) == bound)
            {
                return (int)((bound) * (long)Next(31) >> 31);
            }

            int bits;
            int val;
            do
            {
                bits = Next(31);
                val = bits % bound;
            }
            while (bits - val + (bound - 1) < 0);

            return val;
        }

        public static byte[] GetRandomLengthBytes(int maxSize)
        {
            return GetSecretBytes((uint)(NextInt(maxSize) + 1));
        }

        public static void ReadFully(Stream input, byte[] buffer) //TODO check for stream empty
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

        public static void Copy(Stream input, Stream output)
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

        public static int ToIntExact(long value)
        {
            if ((int)value != value)
            {
                throw new ArithmeticException("integer overflow");
            }
            return (int)value;
        }

        public static long CurrentTimeMillis()
        {
            return (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Ticks / TimeSpan.TicksPerMillisecond;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
