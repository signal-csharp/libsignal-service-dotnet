/** 
 * Copyright (C) 2015 smndtrl
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
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libsignalservice.util
{
    public class Base64
    {
        /*public static byte[] encodeBytes(byte[] input)
        {
            char[] chars = System.Text.Encoding.UTF8.GetString(input, 0, input.Length).ToCharArray();
            return Convert.ToBase64String(input);
        }*/

        public static string encodeBytes(byte[] input)
        {
            return Convert.ToBase64String(input);
        }

        public static string encodeBytesWithoutPadding(byte[] input)
        {
            String encoded = null;


            encoded = encodeBytes(input);

            if (encoded[encoded.Length - 2] == '=') return encoded.Substring(0, encoded.Length - 2);
            else if (encoded[encoded.Length - 1] == '=') return encoded.Substring(0, encoded.Length - 1);
            else return encoded;
        }

        /*public static byte[] encodeWithoutPadding(byte[] input)
        {
            char[] chars = System.Text.Encoding.UTF8.GetString(input, 0, input.Length).ToCharArray();
            return Convert.ToBase64CharArray(chars, 0, chars.Length);
        }*/

        public static byte[] encode(byte[] input)
        {
            char[] chars = System.Text.Encoding.UTF8.GetString(input, 0, input.Length).ToCharArray();
            return Encoding.UTF8.GetBytes(Convert.ToBase64String(input));
        }
        public static byte[] decode(string input)
        {
            return Convert.FromBase64String(input);
        }

        public static byte[] decodeWithoutPadding(string input)
        {
            int padding = input.Length % 4;

            if (padding == 1) input = input + "=";
            else if (padding == 2) input = input + "==";
            else if (padding == 3) input = input + "=";

            return decode(input);
        }
    }
}
