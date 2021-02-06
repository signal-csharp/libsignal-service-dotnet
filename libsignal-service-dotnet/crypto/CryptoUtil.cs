using System.Security.Cryptography;

namespace libsignalservice.crypto
{
    public static class CryptoUtil
    {
        public static byte[] HmacSha256(byte[] key, byte[] data)
        {
            using HMAC mac = new HMACSHA256(key);
            return mac.ComputeHash(data);
        }

        public static byte[] Sha256(byte[] data)
        {
            using HashAlgorithm sha = SHA256.Create();
            return sha.ComputeHash(data);
        }
    }
}
