namespace libsignalservice
{
    public static class HelperMethods
    {
        // taken from https://stackoverflow.com/a/14333437/6681022
        public static string ByteArrayToHexString(byte[]? bytes)
        {
            if (bytes == null)
            {
                return string.Empty;
            }

            char[] c = new char[bytes.Length * 2];
            int b;
            for (int i = 0; i < bytes.Length; i++)
            {
                b = bytes[i] >> 4;
                c[i * 2] = (char)(55 + b + (((b-10)>>31)&-7));
                b = bytes[i] & 0xF;
                c[i * 2 + 1] = (char)(55 + b + (((b-10)>>31)&-7));
            }
            return new string(c);
        }
    }
}
