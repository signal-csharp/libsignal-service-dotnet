using System.Security.Cryptography;

namespace libsignalservice.util
{
    internal class Hash
    {
        public static byte[] Sha1(byte[] input)
        {
            using (SHA1 sha = SHA1.Create())
            {
                return sha.ComputeHash(input);
            }
        }
    }
}
