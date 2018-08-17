using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

        public static HttpClient CreateHttpClient()
        {
            HttpClient client;
            HttpClientHandler handler = new HttpClientHandler();
            try
            {
                handler.ServerCertificateCustomValidationCallback = IsCorrectCertificate;
                client = new HttpClient(handler);
            }
            catch (Exception)
            {
                client = new HttpClient();
            }
            return client;
        }

        private static bool IsCorrectCertificate(HttpRequestMessage a, X509Certificate2 b, X509Chain c, SslPolicyErrors d)
        {
			return d == SslPolicyErrors.None || b.RawData.SequenceEqual(Certificate);
		}

        public static readonly byte[] Certificate = new byte[] {
            48, 130, 4, 22, 48, 130, 2, 254, 160, 3, 2, 1, 2, 2, 2, 16, 3,
            48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 5, 5, 0, 48, 129,
            141, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48,
            17, 6, 3, 85, 4, 8, 12, 10, 67, 97, 108, 105, 102, 111, 114, 110,
            105, 97, 49, 22, 48, 20, 6, 3, 85, 4, 7, 12, 13, 83, 97, 110, 32,
            70, 114, 97, 110, 99, 105, 115, 99, 111, 49, 29, 48, 27, 6, 3, 85,
            4, 10, 12, 20, 79, 112, 101, 110, 32, 87, 104, 105, 115, 112, 101,
            114, 32, 83, 121, 115, 116, 101, 109, 115, 49, 29, 48, 27, 6, 3, 85,
            4, 11, 12, 20, 79, 112, 101, 110, 32, 87, 104, 105, 115, 112, 101, 114,
            32, 83, 121, 115, 116, 101, 109, 115, 49, 19, 48, 17, 6, 3, 85, 4, 3,
            12, 10, 84, 101, 120, 116, 83, 101, 99, 117, 114, 101, 48, 30, 23,
            13, 49, 51, 48, 52, 48, 55, 48, 48, 48, 48, 48, 48, 90, 23, 13, 50, 52,
            48, 52, 48, 55, 48, 51, 51, 55, 52, 50, 90, 48, 129, 144, 49, 11, 48, 9, 6, 3,
            85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 67,
            97, 108, 105, 102, 111, 114, 110, 105, 97, 49, 29, 48, 27, 6, 3, 85,
            4, 10, 12, 20, 79, 112, 101, 110, 32, 87, 104, 105, 115, 112, 101, 114,
            32, 83, 121, 115, 116, 101, 109, 115, 49, 29, 48, 27, 6, 3, 85, 4, 11,
            12, 20, 79, 112, 101, 110, 32, 87, 104, 105, 115, 112, 101, 114, 32, 83,
            121, 115, 116, 101, 109, 115, 49, 46, 48, 44, 6, 3, 85, 4, 3, 12, 37, 116,
            101, 120, 116, 115, 101, 99, 117, 114, 101, 45, 115, 101, 114, 118, 105,
            99, 101, 46, 119, 104, 105, 115, 112, 101, 114, 115, 121, 115, 116, 101,
            109, 115, 46, 111, 114, 103, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72,
            134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1,
            1, 0, 166, 79, 1, 0, 106, 219, 198, 236, 24, 67, 165, 135, 15, 246, 197,
            4, 62, 43, 74, 237, 58, 210, 78, 249, 153, 122, 41, 209, 114, 84, 151, 200,
            73, 140, 190, 124, 128, 166, 243, 203, 171, 62, 101, 241, 15, 224, 159, 176,
            218, 190, 175, 137, 110, 102, 90, 206, 86, 130, 241, 121, 6, 34, 163, 181, 218,
            198, 206, 52, 148, 172, 10, 226, 76, 209, 110, 137, 154, 157, 173, 156, 33, 110,
            101, 10, 12, 204, 7, 242, 249, 222, 168, 184, 88, 222, 184, 35, 252, 154, 81, 82,
            4, 142, 155, 24, 128, 150, 53, 245, 47, 41, 63, 188, 247, 158, 161, 20, 220, 142,
            179, 199, 130, 28, 195, 172, 25, 111, 43, 161, 1, 213, 114, 169, 211, 150, 107,
            96, 97, 125, 191, 50, 181, 158, 127, 195, 116, 2, 226, 194, 72, 105, 48, 222, 65,
            232, 76, 91, 66, 187, 19, 92, 75, 48, 158, 111, 167, 96, 204, 168, 4, 59, 16, 206,
            74, 204, 34, 6, 174, 183, 82, 149, 159, 172, 7, 52, 164, 127, 73, 131, 14, 49, 33,
            192, 144, 106, 97, 112, 162, 222, 71, 49, 235, 121, 66, 78, 109, 116, 43, 81, 61,
            154, 229, 216, 143, 238, 246, 245, 23, 172, 160, 43, 109, 57, 190, 165, 228, 42, 33,
            24, 119, 156, 109, 7, 51, 159, 84, 118, 82, 51, 200, 105, 82, 191, 231, 113, 55, 73,
            209, 244, 132, 140, 244, 93, 152, 160, 247, 153, 2, 3, 1, 0, 1, 163, 123, 48, 121,
            48, 9, 6, 3, 85, 29, 19, 4, 2, 48, 0, 48, 44, 6, 9, 96, 134, 72, 1, 134, 248, 66, 1,
            13, 4, 31, 22, 29, 79, 112, 101, 110, 83, 83, 76, 32, 71, 101, 110, 101, 114, 97, 116,
            101, 100, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 48, 29, 6, 3, 85,
            29, 14, 4, 22, 4, 20, 7, 224, 19, 80, 129, 57, 15, 48, 24, 219, 92, 76, 198, 87, 228,
            128, 221, 241, 229, 152, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 1, 139, 24,
            241, 63, 251, 57, 25, 68, 110, 133, 134, 190, 148, 101, 50, 167, 50, 60, 144, 48, 13,
            6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 5, 5, 0, 3, 130, 1, 1, 0, 178, 5, 80, 109, 199,
            7, 199, 157, 127, 97, 232, 142, 78, 92, 88, 91, 249, 18, 133, 99, 136, 4, 71, 7, 40,
            198, 171, 27, 87, 92, 17, 217, 243, 148, 39, 197, 154, 255, 155, 229, 174, 177, 21,
            90, 18, 88, 222, 211, 47, 127, 104, 93, 185, 158, 199, 51, 174, 170, 188, 61, 0, 93,
            223, 129, 97, 143, 146, 248, 83, 179, 59, 63, 14, 154, 183, 5, 7, 133, 230, 234, 174,
            217, 5, 99, 245, 206, 186, 119, 37, 38, 213, 108, 67, 84, 83, 254, 58, 159, 54, 16,
            81, 106, 160, 234, 75, 139, 231, 39, 251, 168, 237, 51, 213, 210, 155, 42, 52, 159,
            150, 232, 123, 236, 147, 37, 194, 71, 109, 92, 163, 23, 10, 223, 209, 253, 157, 252,
            100, 185, 6, 92, 165, 102, 155, 25, 106, 19, 209, 217, 49, 72, 117, 243, 46, 154, 42,
            160, 235, 31, 41, 245, 142, 113, 202, 123, 213, 106, 96, 5, 149, 0, 164, 148, 79, 179,
            205, 203, 91, 98, 57, 29, 184, 232, 149, 158, 85, 57, 230, 128, 13, 215, 213, 196, 117,
            139, 212, 58, 231, 252, 240, 160, 71, 12, 227, 100, 64, 236, 179, 63, 1, 80, 103, 9,
            46, 109, 132, 210, 108, 189, 76, 35, 44, 181, 11, 20, 190, 115, 195, 221, 220, 90, 81,
            139, 39, 151, 230, 27, 91, 185, 127, 22, 186, 159, 55, 99, 185, 75, 250, 189, 227, 102,
            114, 97, 21, 93, 117, 232 };
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
