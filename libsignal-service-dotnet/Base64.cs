using System;
using System.Text;

namespace libsignalservice.util
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class Base64
    {
        public static string EncodeBytes(byte[] input)
        {
            return Convert.ToBase64String(input);
        }

        public static string EncodeBytesWithoutPadding(byte[] input)
        {
            String encoded = null;

            encoded = EncodeBytes(input);

            if (encoded[encoded.Length - 2] == '=') return encoded.Substring(0, encoded.Length - 2);
            else if (encoded[encoded.Length - 1] == '=') return encoded.Substring(0, encoded.Length - 1);
            else return encoded;
        }

        public static byte[] Encode(byte[] input)
        {
            char[] chars = System.Text.Encoding.UTF8.GetString(input, 0, input.Length).ToCharArray();
            return Encoding.UTF8.GetBytes(Convert.ToBase64String(input));
        }

        public static byte[] Decode(string input)
        {
            return Convert.FromBase64String(input);
        }

        public static byte[] DecodeWithoutPadding(string input)
        {
            int padding = input.Length % 4;

            if (padding == 1) input = input + "=";
            else if (padding == 2) input = input + "==";
            else if (padding == 3) input = input + "=";

            return Decode(input);
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
