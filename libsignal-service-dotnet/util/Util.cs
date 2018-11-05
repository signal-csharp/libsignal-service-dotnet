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
            48, 130, 4, 22, 48, 130, 2, 254, 160, 3, 2, 1, 2, 2, 2, 16, 15, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11,
            5, 0, 48, 129, 141, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 67, 97, 108,
            105, 102, 111, 114, 110, 105, 97, 49, 22, 48, 20, 6, 3, 85, 4, 7, 12, 13, 83, 97, 110, 32, 70, 114, 97, 110, 99, 105, 115,
            99, 111, 49, 29, 48, 27, 6, 3, 85, 4, 10, 12, 20, 79, 112, 101, 110, 32, 87, 104, 105, 115, 112, 101, 114, 32, 83, 121, 115,
            116, 101, 109, 115, 49, 29, 48, 27, 6, 3, 85, 4, 11, 12, 20, 79, 112, 101, 110, 32, 87, 104, 105, 115, 112, 101, 114, 32, 83,
            121, 115, 116, 101, 109, 115, 49, 19, 48, 17, 6, 3, 85, 4, 3, 12, 10, 84, 101, 120, 116, 83, 101, 99, 117, 114, 101, 48, 30,
            23, 13, 49, 56, 49, 49, 48, 50, 48, 56, 49, 48, 48, 52, 90, 23, 13, 50, 56, 49, 48, 51, 48, 48, 56, 49, 48, 48, 52, 90, 48,
            129, 144, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 67, 97, 108, 105, 102, 111,
            114, 110, 105, 97, 49, 29, 48, 27, 6, 3, 85, 4, 10, 12, 20, 79, 112, 101, 110, 32, 87, 104, 105, 115, 112, 101, 114, 32, 83,
            121, 115, 116, 101, 109, 115, 49, 29, 48, 27, 6, 3, 85, 4, 11, 12, 20, 79, 112, 101, 110, 32, 87, 104, 105, 115, 112, 101, 114,
            32, 83, 121, 115, 116, 101, 109, 115, 49, 46, 48, 44, 6, 3, 85, 4, 3, 12, 37, 116, 101, 120, 116, 115, 101, 99, 117, 114, 101,
            45, 115, 101, 114, 118, 105, 99, 101, 46, 119, 104, 105, 115, 112, 101, 114, 115, 121, 115, 116, 101, 109, 115, 46, 111, 114,
            103, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1,
            0, 192, 61, 225, 20, 156, 163, 134, 153, 245, 240, 16, 12, 232, 229, 57, 48, 231, 75, 240, 20, 233, 143, 92, 148, 182, 97, 127,
            82, 172, 201, 197, 152, 130, 116, 55, 41, 120, 96, 157, 168, 201, 119, 238, 109, 197, 230, 211, 188, 139, 42, 95, 172, 187, 16,
            67, 248, 172, 71, 41, 242, 223, 233, 89, 26, 245, 162, 119, 232, 252, 235, 246, 38, 236, 164, 226, 171, 113, 230, 156, 248, 101,
            94, 98, 98, 109, 139, 47, 223, 78, 63, 230, 196, 61, 186, 202, 60, 131, 95, 101, 7, 146, 51, 149, 250, 153, 143, 199, 167, 172,
            231, 76, 153, 160, 134, 63, 154, 111, 24, 103, 177, 244, 69, 232, 236, 157, 196, 88, 101, 230, 108, 111, 152, 76, 152, 11, 153,
            128, 238, 230, 227, 248, 27, 63, 195, 117, 84, 185, 87, 254, 124, 90, 50, 19, 66, 49, 228, 223, 227, 11, 71, 88, 85, 5, 7, 184,
            169, 107, 60, 162, 124, 116, 0, 173, 219, 218, 78, 103, 119, 137, 53, 222, 5, 87, 137, 102, 164, 60, 173, 66, 171, 8, 6, 30, 8,
            145, 87, 172, 41, 235, 202, 206, 88, 107, 72, 231, 220, 43, 101, 150, 210, 53, 24, 30, 93, 140, 242, 149, 30, 25, 58, 101, 170,
            177, 131, 98, 240, 234, 140, 166, 202, 240, 76, 155, 42, 50, 27, 35, 15, 41, 49, 39, 156, 192, 234, 113, 50, 215, 165, 60, 244,
            122, 117, 105, 30, 148, 119, 2, 3, 1, 0, 1, 163, 123, 48, 121, 48, 9, 6, 3, 85, 29, 19, 4, 2, 48, 0, 48, 44, 6, 9, 96, 134, 72,
            1, 134, 248, 66, 1, 13, 4, 31, 22, 29, 79, 112, 101, 110, 83, 83, 76, 32, 71, 101, 110, 101, 114, 97, 116, 101, 100, 32, 67, 101,
            114, 116, 105, 102, 105, 99, 97, 116, 101, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 170, 209, 152, 190, 118, 0, 1, 240, 150, 101,
            42, 167, 186, 122, 196, 239, 113, 236, 63, 166, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 1, 139, 24, 241, 63, 251, 57,
            25, 68, 110, 133, 134, 190, 148, 101, 50, 167, 50, 60, 144, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1,
            1, 0, 121, 126, 210, 50, 193, 158, 1, 249, 40, 111, 106, 21, 114, 186, 88, 21, 170, 251, 18, 237, 79, 129, 206, 108, 61, 255, 244,
            186, 109, 113, 75, 8, 80, 42, 159, 21, 59, 35, 242, 157, 248, 227, 97, 240, 125, 6, 37, 160, 158, 137, 87, 47, 60, 92, 218, 16,
            197, 122, 120, 249, 96, 41, 198, 103, 198, 26, 247, 191, 150, 226, 198, 57, 89, 157, 123, 183, 103, 133, 34, 49, 40, 32, 184, 34,
            106, 139, 204, 9, 196, 210, 241, 160, 179, 91, 106, 202, 128, 231, 54, 5, 17, 173, 55, 94, 8, 202, 34, 225, 151, 220, 73, 225, 204,
            138, 224, 119, 223, 144, 217, 8, 247, 65, 152, 188, 158, 223, 190, 189, 62, 65, 222, 212, 199, 101, 64, 166, 142, 243, 15, 137, 175,
            73, 62, 193, 20, 188, 239, 104, 110, 159, 98, 78, 133, 197, 165, 107, 44, 94, 211, 184, 38, 82, 205, 197, 246, 14, 6, 86, 116, 225,
            153, 197, 103, 46, 172, 191, 178, 233, 124, 226, 24, 213, 219, 58, 162, 87, 19, 91, 224, 133, 217, 217, 185, 18, 92, 57, 11, 173,
            162, 8, 177, 41, 144, 98, 47, 197, 35, 90, 204, 154, 57, 177, 140, 205, 169, 30, 25, 37, 88, 252, 223, 72, 64, 132, 73, 252, 143,
            232, 175, 0, 68, 145, 173, 25, 72, 30, 200, 76, 177, 235, 42, 38, 132, 105, 153, 254, 184, 103, 221, 234, 201, 21, 0, 103, 136, 96 };
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
