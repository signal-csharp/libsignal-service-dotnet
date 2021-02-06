using System;
using System.IO;

namespace libsignalservice.contacts.crypto
{
    internal class Quote
    {
        private static readonly ulong SGX_FLAGS_INITTED = 0x0000_0000_0000_0001L;
        private static readonly ulong SGX_FLAGS_DEBUG = 0x0000_0000_0000_0002L;
        private static readonly ulong SGX_FLAGS_MODE64BIT = 0x0000_0000_0000_0004L;
        private static readonly ulong SGX_FLAGS_PROVISION_KEY = 0x0000_0000_0000_0004L;
        private static readonly ulong SGX_FLAGS_EINITTOKEN_KEY = 0x0000_0000_0000_0004L;
        /// <summary>
        /// Cannot be converted to long
        /// </summary>
        private static readonly ulong SGX_FLAGS_RESERVED = 0xFFFF_FFFF_FFFF_FFC8L;
        private static readonly ulong SGX_XFRM_LEGACY = 0x0000_0000_0000_0003L;
        private static readonly ulong SGX_XFRM_AVX = 0x0000_0000_0000_0006L;
        /// <summary>
        /// Cannot be converted to long
        /// </summary>
        private static readonly ulong SGX_XFRM_RESERVED = 0xFFFF_FFFF_FFFF_FFF8L;

        private readonly int version;
        private readonly bool isSigLinkable;
        private readonly long gid;
        private readonly int qeSvn;
        private readonly int pceSvn;
        private readonly byte[] basename = new byte[32];
        private readonly byte[] cpuSvn = new byte[16];
        private readonly ulong flags;
        private readonly ulong xfrm;
        public byte[] Mrenclave { get; } = new byte[32];
        private readonly byte[] mrsigner = new byte[32];
        private readonly int isvProdId;
        private readonly int isvSvn;
        public byte[] ReportData { get; } = new byte[64];
        private readonly byte[] signature;
        public byte[] QuoteBytes { get; }

        public Quote(byte[] quoteBytes)
        {
            QuoteBytes = quoteBytes;

            // BinaryReader stores writes as little endian
            BinaryReader quoteBuf = new BinaryReader(new MemoryStream(quoteBytes));

            version = quoteBuf.ReadUInt16() & 0xFFFF;
            if (!(version >= 1 && version <= 2))
            {
                throw new InvalidQuoteFormatException($"unknown_quote_version {version}");
            }

            int sign_type = quoteBuf.ReadUInt16() & 0xFFFF;
            if ((sign_type & ~1) != 0)
            {
                throw new InvalidQuoteFormatException($"unknown_quote_sign_type {sign_type}");
            }

            isSigLinkable = sign_type == 1;
            gid = quoteBuf.ReadUInt32() & 0xFFFF_FFFF;
            qeSvn = quoteBuf.ReadUInt16() & 0xFFFF;

            if (version > 1)
            {
                pceSvn = quoteBuf.ReadUInt16() & 0xFFFF;
            }
            else
            {
                ReadZero(quoteBuf, 10, 2);
                pceSvn = 0;
            }

            ReadZero(quoteBuf, 12, 4); // xeid (reserved)
            Read(quoteBuf, 16, basename);

            //
            // report_body
            //

            Read(quoteBuf, 48, cpuSvn);
            ReadZero(quoteBuf, 64, 4); // misc_select (reserved)
            ReadZero(quoteBuf, 68, 28); // reserved1
            flags = quoteBuf.ReadUInt64();
            if ((flags & SGX_FLAGS_RESERVED) != 0 ||
                (flags & SGX_FLAGS_INITTED) == 0 ||
                (flags & SGX_FLAGS_MODE64BIT) == 0)
            {
                throw new InvalidQuoteFormatException($"bad_quote_flags {flags}");
            }
            xfrm = quoteBuf.ReadUInt64();
            if ((xfrm & SGX_XFRM_RESERVED) != 0)
            {
                throw new InvalidQuoteFormatException($"bad_quote_xfrm {xfrm}");
            }
            Read(quoteBuf, 112, Mrenclave);
            ReadZero(quoteBuf, 144, 32); // reserved2
            Read(quoteBuf, 176, mrsigner);
            ReadZero(quoteBuf, 208, 96); // reserved3
            isvProdId = quoteBuf.ReadUInt16() & 0xFFFF;
            isvSvn = quoteBuf.ReadUInt16() & 0xFFFF;
            ReadZero(quoteBuf, 308, 60); // reserved4
            Read(quoteBuf, 368, ReportData);

            // quote signature
            uint sig_len = quoteBuf.ReadUInt32() & 0xFFFF_FFFF;
            if (sig_len != quoteBytes.Length - 436)
            {
                throw new InvalidQuoteFormatException($"bad_quote_sig_len {sig_len}");
            }
            signature = new byte[sig_len];
            Read(quoteBuf, 436, signature);
        }

        private void Read(BinaryReader quoteBuf, int pos, byte[] buf)
        {
            quoteBuf.BaseStream.Position = pos;
            quoteBuf.Read(buf, 0, buf.Length);
        }

        private void ReadZero(BinaryReader quoteBuf, int pos, int count)
        {
            byte[] zeroBuf = new byte[count];
            Read(quoteBuf, pos, zeroBuf);
            for (int zeroBufIdx = 0; zeroBufIdx < count; zeroBufIdx++)
            {
                if (zeroBuf[zeroBufIdx] != 0)
                {
                    throw new ArgumentException($"quote_reserved_mismatch {pos}");
                }
            }
        }

        public bool IsDebugQuote()
        {
            return (flags & SGX_FLAGS_DEBUG) != 0;
        }

        public class InvalidQuoteFormatException : Exception
        {
            public InvalidQuoteFormatException(string value) : base(value)
            {
            }
        }
    }
}
