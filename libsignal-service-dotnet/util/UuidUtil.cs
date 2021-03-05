using System;
using System.IO;
using System.Text.RegularExpressions;
using Be.IO;

namespace libsignalservice.util
{
    public static class UuidUtil
    {
        private static Regex UUID_PATTERN = new Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", RegexOptions.IgnoreCase);

        public static Guid? Parse(string? uuid)
        {
            return ParseOrNull(uuid);
        }

        public static Guid? ParseOrNull(string? uuid)
        {
            return IsUuid(uuid) ? ParseOrThrow(uuid!) : (Guid?)null;
        }

        public static Guid ParseOrThrow(string uuid)
        {
            return Guid.Parse(uuid);
        }

        public static Guid ParseOrThrow(byte[] bytes)
        {
            using MemoryStream stream = new MemoryStream(bytes);
            // Needs to be big-endian because the Java ByteBuffer defaults to big-endian.
            using BeBinaryReader byteBuffer = new BeBinaryReader(stream);
            long high = byteBuffer.ReadInt64();
            long low = byteBuffer.ReadInt64();

            return JavaUUIDToCSharpGuid(high, low);
        }

        public static bool IsUuid(string? uuid)
        {
            return uuid != null && UUID_PATTERN.IsMatch(uuid);
        }

        public static byte[] ToByteArray(Guid uuid)
        {
            using MemoryStream stream = new MemoryStream(new byte[16]);
            // Needs to be big-endian because the Java ByteBuffer defaults to big-endian.
            using BeBinaryWriter buffer = new BeBinaryWriter(stream);
            buffer.Write(uuid.GetMostSignificantBits());
            buffer.Write(uuid.GetLeastSignificantBits());

            return stream.ToArray();
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

        /// <summary>
        /// Gets the most significant bits of the Guid
        /// </summary>
        /// <param name="guid">A Guid</param>
        /// <returns>The most significant bits as a long</returns>
        public static long GetMostSignificantBits(this Guid guid)
        {
            byte[] gb = guid.ToByteArray();
            byte[] ms = new byte[8]
            {
                gb[6], gb[7], gb[4], gb[5], gb[0], gb[1], gb[2], gb[3]
            };
            return BitConverter.ToInt64(ms, 0);
        }

        /// <summary>
        /// Gets the least significant bits of the Guid
        /// </summary>
        /// <param name="guid">A Guid</param>
        /// <returns>The least significant bits as a long</returns>
        public static long GetLeastSignificantBits(this Guid guid)
        {
            byte[] gb = guid.ToByteArray();
            byte[] ls = new byte[8]
            {
                gb[15], gb[14], gb[13], gb[12], gb[11], gb[10], gb[9], gb[8]
            };

            return BitConverter.ToInt64(ls, 0);
        }
    }
}
