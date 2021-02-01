using System;
using System.IO;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.util
{
    public static class Hex
    {
        private const int HEX_DIGITS_START = 10;
        private const int ASCII_TEXT_START = HEX_DIGITS_START + (16 * 2 + (16 / 2));

        static readonly string EOL = Environment.NewLine;

        private static readonly char[] HEX_DIGITS =
        {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };

        public static string ToString(byte[] bytes)
        {
            return ToString(bytes, 0, bytes.Length);
        }

        public static string ToString(byte[] bytes, int offset, int length)
        {
            StringBuilder buf = new StringBuilder();
            for (int i = 0; i < length; i++)
            {
                AppendHexChar(buf, bytes[offset + i]);
                buf.Append(' ');
            }
            return buf.ToString();
        }

        public static string ToStringCondensed(byte[] bytes)
        {
            StringBuilder buf = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                AppendHexChar(buf, bytes[i]);
            }
            return buf.ToString();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="encoded"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public static byte[] FromStringCondensed(string encoded)
        {
            char[] data = encoded.ToCharArray();
            int len = data.Length;

            if ((len & 0x01) != 0)
            {
                throw new IOException("Odd number of characters.");
            }

            byte[] _out = new byte[len >> 1];

            // two characters form the hex value.
            for (int i = 0, j = 0; j < len; i++)
            {
                int f = Convert.ToInt32(data[j].ToString(), 16) << 4;
                j++;
                f = f | Convert.ToInt32(data[j].ToString(), 16);
                j++;
                _out[i] = (byte)(f & 0xFF);
            }

            return _out;
        }

        public static string Dump(byte[] bytes)
        {
            return Dump(bytes, 0, bytes.Length);
        }

        public static string Dump(byte[] bytes, int offset, int length)
        {
            StringBuilder buf = new StringBuilder();
            int lines = ((length - 1) / 16) + 1;
            int lineOffset;
            int lineLength;

            for (int i = 0; i < lines; i++)
            {
                lineOffset = (i * 16) + offset;
                lineLength = Math.Min(16, (length - (i * 16)));
                AppendDumpLine(buf, i, bytes, lineOffset, lineLength);
                buf.Append(EOL);
            }

            return buf.ToString();
        }

        private static void AppendDumpLine(StringBuilder buf, int line, byte[] bytes, int lineOffset, int lineLength)
        {
            buf.Append(HEX_DIGITS[(line >> 28) & 0xf]);
            buf.Append(HEX_DIGITS[(line >> 24) & 0xf]);
            buf.Append(HEX_DIGITS[(line >> 20) & 0xf]);
            buf.Append(HEX_DIGITS[(line >> 16) & 0xf]);
            buf.Append(HEX_DIGITS[(line >> 12) & 0xf]);
            buf.Append(HEX_DIGITS[(line >>  8) & 0xf]);
            buf.Append(HEX_DIGITS[(line >>  4) & 0xf]);
            buf.Append(HEX_DIGITS[(line) & 0xf]);
            buf.Append(": ");

            for (int i = 0; i < 16; i++)
            {
                int idx = i + lineOffset;
                if (i < lineLength)
                {
                    int b = bytes[idx];
                    AppendHexChar(buf, b);
                }
                else
                {
                    buf.Append(" ");
                }
            }

            for (int i = 0; i < 16 && i < lineLength; i++)
            {
                int idx = i + lineOffset;
                int b = bytes[idx];
                if (b >= 0x20 && b <= 0x7e)
                {
                    buf.Append((char)b);
                }
                else
                {
                    buf.Append('.');
                }
            }
        }

        private static void AppendHexChar(StringBuilder buf, int b)
        {
            buf.Append(HEX_DIGITS[(b >> 4) & 0xf]);
            buf.Append(HEX_DIGITS[b & 0xf]);
        }
    }
}
