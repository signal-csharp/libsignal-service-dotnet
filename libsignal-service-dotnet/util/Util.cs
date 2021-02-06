using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace libsignalservice.util
{
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

        /// <summary>
        /// Converts the expected Java UUID constructor parameters into a C# Guid
        /// </summary>
        /// <param name="mostSigBits">The most significant bits of the UUID</param>
        /// <param name="leastSigBits">The least significant bits of the UUID</param>
        /// <returns>A Guid</returns>
        public static Guid JavaUUIDToCSharpGuid(long mostSigBits, long leastSigBits)
        {
            byte[] ms = BitConverter.GetBytes(mostSigBits);
            byte[] ls = BitConverter.GetBytes(leastSigBits);

            byte[] guidBytes = new byte[16]
            {
                ms[4], ms[5], ms[6], ms[7], ms[2], ms[3], ms[0], ms[1],
                ls[7], ls[6], ls[5], ls[4], ls[3], ls[2], ls[1], ls[0]
            };

            return new Guid(guidBytes);
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
            return d == SslPolicyErrors.None ||
                b.RawData.SequenceEqual(SignalServiceCertificate) ||
                b.RawData.SequenceEqual(SignalContactDiscoveryServiceCertificate);
        }
        
        public static readonly byte[] SignalServiceCertificate = new byte[] {
            48, 130, 3, 227, 48, 130, 2, 203, 160, 3, 2, 1, 2, 2, 2, 16, 24, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1,
            11, 5, 0, 48, 129, 141, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 67,
            97, 108, 105, 102, 111, 114, 110, 105, 97, 49, 22, 48, 20, 6, 3, 85, 4, 7, 12, 13, 83, 97, 110, 32, 70, 114, 97,
            110, 99, 105, 115, 99, 111, 49, 29, 48, 27, 6, 3, 85, 4, 10, 12, 20, 79, 112, 101, 110, 32, 87, 104, 105, 115,
            112, 101, 114, 32, 83, 121, 115, 116, 101, 109, 115, 49, 29, 48, 27, 6, 3, 85, 4, 11, 12, 20, 79, 112, 101, 110,
            32, 87, 104, 105, 115, 112, 101, 114, 32, 83, 121, 115, 116, 101, 109, 115, 49, 19, 48, 17, 6, 3, 85, 4, 3, 12,
            10, 84, 101, 120, 116, 83, 101, 99, 117, 114, 101, 48, 30, 23, 13, 49, 57, 48, 50, 49, 53, 49, 55, 51, 56, 49,
            55, 90, 23, 13, 50, 57, 48, 51, 49, 50, 49, 56, 50, 48, 50, 48, 90, 48, 129, 144, 49, 11, 48, 9, 6, 3, 85, 4, 6,
            19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 67, 97, 108, 105, 102, 111, 114, 110, 105, 97, 49, 29, 48,
            27, 6, 3, 85, 4, 10, 12, 20, 79, 112, 101, 110, 32, 87, 104, 105, 115, 112, 101, 114, 32, 83, 121, 115, 116, 101,
            109, 115, 49, 29, 48, 27, 6, 3, 85, 4, 11, 12, 20, 79, 112, 101, 110, 32, 87, 104, 105, 115, 112, 101, 114, 32,
            83, 121, 115, 116, 101, 109, 115, 49, 46, 48, 44, 6, 3, 85, 4, 3, 12, 37, 116, 101, 120, 116, 115, 101, 99, 117,
            114, 101, 45, 115, 101, 114, 118, 105, 99, 101, 46, 119, 104, 105, 115, 112, 101, 114, 115, 121, 115, 116, 101,
            109, 115, 46, 111, 114, 103, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1,
            15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 172, 200, 17, 181, 209, 69, 183, 192, 162, 203, 207, 147, 137, 154, 128,
            117, 179, 176, 120, 112, 59, 59, 187, 58, 126, 196, 3, 140, 113, 169, 88, 135, 108, 222, 40, 199, 136, 229, 228,
            184, 125, 154, 238, 167, 85, 109, 30, 6, 252, 92, 247, 52, 10, 60, 109, 34, 142, 4, 9, 55, 244, 149, 231, 120,
            197, 194, 58, 170, 182, 190, 9, 97, 59, 7, 204, 171, 58, 110, 1, 229, 96, 126, 172, 91, 117, 199, 197, 227, 227,
            228, 145, 74, 73, 37, 214, 99, 185, 74, 52, 4, 149, 151, 146, 164, 74, 104, 90, 137, 130, 45, 16, 241, 49, 189, 42,
            15, 7, 214, 205, 194, 234, 98, 197, 158, 64, 123, 72, 136, 19, 243, 88, 64, 14, 178, 101, 122, 80, 77, 141, 29, 5,
            77, 37, 214, 173, 41, 65, 229, 243, 45, 122, 160, 37, 235, 83, 135, 52, 151, 175, 168, 249, 178, 131, 78, 216, 172,
            145, 160, 192, 77, 108, 142, 54, 124, 245, 24, 189, 100, 66, 57, 71, 242, 80, 210, 54, 125, 189, 234, 178, 230, 67,
            249, 4, 59, 96, 172, 101, 230, 24, 3, 5, 79, 40, 52, 35, 77, 243, 75, 13, 90, 56, 97, 230, 113, 68, 57, 97, 163,
            230, 92, 101, 214, 166, 19, 146, 157, 236, 88, 146, 70, 96, 62, 156, 185, 0, 201, 212, 58, 210, 40, 214, 195, 81,
            105, 236, 148, 135, 190, 194, 246, 95, 79, 31, 126, 146, 109, 2, 3, 1, 0, 1, 163, 72, 48, 70, 48, 68, 6, 3, 85, 29,
            17, 4, 61, 48, 59, 130, 37, 116, 101, 120, 116, 115, 101, 99, 117, 114, 101, 45, 115, 101, 114, 118, 105, 99, 101,
            46, 119, 104, 105, 115, 112, 101, 114, 115, 121, 115, 116, 101, 109, 115, 46, 111, 114, 103, 130, 18, 115, 101, 114,
            118, 105, 99, 101, 46, 115, 105, 103, 110, 97, 108, 46, 111, 114, 103, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1,
            11, 5, 0, 3, 130, 1, 1, 0, 41, 107, 46, 71, 188, 247, 12, 63, 225, 196, 218, 244, 183, 88, 236, 75, 255, 40, 6, 214,
            143, 234, 227, 55, 14, 253, 86, 14, 124, 14, 234, 219, 40, 133, 55, 97, 67, 23, 201, 68, 115, 1, 42, 112, 51, 0, 207,
            111, 161, 24, 175, 223, 94, 45, 160, 104, 134, 42, 233, 250, 119, 124, 191, 78, 183, 50, 43, 94, 101, 13, 8, 29, 136,
            244, 250, 110, 35, 136, 227, 235, 21, 45, 17, 23, 156, 57, 116, 154, 28, 77, 130, 221, 50, 55, 183, 176, 136, 114,
            248, 91, 25, 77, 78, 172, 152, 131, 45, 181, 69, 28, 79, 17, 1, 235, 108, 36, 156, 157, 217, 133, 174, 204, 28, 29,
            245, 77, 232, 89, 46, 25, 55, 56, 229, 193, 2, 211, 58, 34, 105, 160, 10, 82, 42, 99, 37, 67, 163, 149, 126, 7, 107,
            234, 180, 83, 35, 90, 28, 195, 234, 184, 255, 0, 241, 113, 129, 33, 136, 186, 12, 150, 60, 184, 216, 15, 214, 175, 5,
            243, 201, 67, 3, 145, 192, 45, 100, 116, 227, 145, 64, 46, 72, 184, 175, 159, 141, 248, 156, 183, 24, 93, 169, 76, 80,
            133, 188, 177, 3, 75, 146, 194, 147, 169, 81, 246, 232, 194, 146, 218, 221, 135, 69, 91, 56, 115, 0, 223, 154, 209, 179,
            153, 100, 139, 110, 4, 65, 151, 255, 14, 170, 234, 185, 92, 178, 205, 17, 66, 12, 223, 83, 85, 112, 21, 5, 164, 168, 73 };

        public static readonly byte[] SignalContactDiscoveryServiceCertificate = new byte[] {
            48, 130, 4, 48, 48, 130, 3, 24, 160, 3, 2, 1, 2, 2, 2, 16, 58, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1,
            1, 11, 5, 0, 48, 129, 141, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12,
            10, 67, 97, 108, 105, 102, 111, 114, 110, 105, 97, 49, 22, 48, 20, 6, 3, 85, 4, 7, 12, 13, 83, 97, 110, 32,
            70, 114, 97, 110, 99, 105, 115, 99, 111, 49, 29, 48, 27, 6, 3, 85, 4, 10, 12, 20, 79, 112, 101, 110, 32, 87,
            104, 105, 115, 112, 101, 114, 32, 83, 121, 115, 116, 101, 109, 115, 49, 29, 48, 27, 6, 3, 85, 4, 11, 12, 20,
            79, 112, 101, 110, 32, 87, 104, 105, 115, 112, 101, 114, 32, 83, 121, 115, 116, 101, 109, 115, 49, 19, 48,
            17, 6, 3, 85, 4, 3, 12, 10, 84, 101, 120, 116, 83, 101, 99, 117, 114, 101, 48, 30, 23, 13, 49, 57, 48, 54,
            48, 49, 48, 48, 48, 48, 48, 48, 90, 23, 13, 51, 49, 48, 49, 48, 57, 48, 51, 51, 55, 49, 48, 90, 48, 129,
            131, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 67, 97, 108, 105,
            102, 111, 114, 110, 105, 97, 49, 29, 48, 27, 6, 3, 85, 4, 10, 12, 20, 79, 112, 101, 110, 32, 87, 104, 105,
            115, 112, 101, 114, 32, 83, 121, 115, 116, 101, 109, 115, 49, 29, 48, 27, 6, 3, 85, 4, 11, 12, 20, 79, 112,
            101, 110, 32, 87, 104, 105, 115, 112, 101, 114, 32, 83, 121, 115, 116, 101, 109, 115, 49, 33, 48, 31, 6, 3,
            85, 4, 3, 12, 24, 97, 112, 105, 46, 100, 105, 114, 101, 99, 116, 111, 114, 121, 46, 115, 105, 103, 110, 97,
            108, 46, 111, 114, 103, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1,
            15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 207, 148, 23, 178, 30, 144, 63, 40, 29, 131, 2, 24, 243, 160, 155,
            162, 144, 64, 158, 14, 115, 28, 121, 39, 188, 61, 233, 95, 123, 206, 6, 75, 123, 25, 222, 136, 149, 159,
            137, 149, 239, 208, 21, 185, 90, 169, 49, 79, 78, 229, 63, 85, 125, 104, 79, 131, 136, 115, 150, 83, 53,
            190, 96, 252, 187, 202, 49, 48, 81, 204, 75, 30, 183, 208, 158, 78, 60, 121, 73, 52, 92, 153, 100, 101, 61,
            235, 183, 0, 147, 217, 100, 67, 175, 8, 125, 192, 55, 158, 70, 56, 232, 133, 240, 84, 41, 170, 129, 85, 34,
            20, 148, 21, 45, 123, 138, 228, 107, 222, 33, 139, 3, 66, 161, 159, 66, 39, 147, 74, 137, 162, 228, 46, 6,
            167, 235, 199, 192, 11, 250, 190, 93, 125, 55, 196, 170, 206, 44, 198, 148, 183, 226, 188, 114, 228, 207,
            51, 236, 122, 220, 115, 22, 221, 112, 17, 228, 53, 249, 255, 65, 18, 213, 138, 73, 179, 164, 82, 1, 134, 83,
            28, 119, 208, 188, 162, 186, 27, 199, 239, 89, 191, 87, 19, 179, 41, 123, 155, 222, 76, 107, 172, 230, 253,
            160, 21, 79, 89, 207, 124, 168, 189, 183, 174, 186, 145, 139, 238, 77, 236, 228, 122, 22, 206, 10, 195, 234,
            78, 225, 153, 138, 148, 60, 235, 109, 47, 90, 206, 40, 210, 238, 151, 250, 223, 73, 37, 246, 26, 76, 113,
            197, 148, 5, 62, 26, 230, 51, 9, 2, 3, 1, 0, 1, 163, 129, 161, 48, 129, 158, 48, 9, 6, 3, 85, 29, 19, 4, 2,
            48, 0, 48, 44, 6, 9, 96, 134, 72, 1, 134, 248, 66, 1, 13, 4, 31, 22, 29, 79, 112, 101, 110, 83, 83, 76, 32,
            71, 101, 110, 101, 114, 97, 116, 101, 100, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 48, 29,
            6, 3, 85, 29, 14, 4, 22, 4, 20, 175, 37, 18, 132, 74, 95, 181, 187, 172, 34, 86, 206, 227, 187, 79, 21, 81,
            214, 133, 47, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 1, 139, 24, 241, 63, 251, 57, 25, 68, 110,
            133, 134, 190, 148, 101, 50, 167, 50, 60, 144, 48, 35, 6, 3, 85, 29, 17, 4, 28, 48, 26, 130, 24, 97, 112,
            105, 46, 100, 105, 114, 101, 99, 116, 111, 114, 121, 46, 115, 105, 103, 110, 97, 108, 46, 111, 114, 103, 48,
            13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 88, 26, 158, 239, 214, 185, 20, 229,
            114, 125, 141, 97, 3, 193, 26, 53, 75, 180, 85, 38, 191, 22, 124, 99, 69, 61, 187, 117, 96, 249, 248, 252,
            133, 121, 41, 11, 114, 13, 208, 201, 86, 178, 89, 138, 16, 129, 73, 77, 133, 9, 42, 149, 42, 190, 96, 143,
            186, 24, 239, 177, 165, 10, 10, 193, 117, 16, 38, 178, 119, 57, 122, 78, 222, 167, 65, 153, 156, 239, 135,
            169, 47, 16, 194, 166, 182, 194, 148, 207, 34, 44, 54, 82, 251, 74, 35, 81, 151, 69, 253, 241, 163, 79, 94,
            141, 158, 133, 50, 213, 164, 246, 6, 26, 69, 176, 132, 14, 100, 42, 140, 227, 72, 223, 214, 193, 214, 69,
            43, 47, 158, 136, 207, 187, 207, 205, 204, 117, 129, 185, 24, 237, 28, 163, 9, 252, 143, 100, 157, 169, 14,
            203, 10, 221, 222, 27, 67, 65, 220, 146, 105, 213, 62, 238, 236, 10, 70, 117, 255, 105, 212, 105, 190, 189,
            236, 98, 47, 248, 113, 30, 108, 30, 231, 250, 108, 9, 139, 233, 224, 129, 137, 158, 50, 78, 70, 19, 67, 75,
            15, 140, 1, 24, 10, 176, 182, 30, 196, 15, 125, 131, 29, 0, 243, 204, 90, 227, 37, 198, 4, 67, 38, 70, 19,
            247, 45, 124, 141, 191, 69, 92, 94, 177, 85, 254, 199, 132, 245, 144, 101, 73, 158, 202, 109, 44, 62, 199,
            77, 19, 107, 138, 4, 75, 168, 217, 134, 87, 198, 177 };
    }
}
