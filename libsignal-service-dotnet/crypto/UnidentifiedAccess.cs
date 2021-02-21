using libsignal.util;
using libsignalmetadatadotnet.certificate;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace libsignalservicedotnet.crypto
{
    public class UnidentifiedAccess
    {
        public byte[] UnidentifiedAccessKey { get; }
        public SenderCertificate UnidentifiedCertificate { get; }

        public UnidentifiedAccess(byte[] unidentifiedAccessKey, byte[] unidentifiedCertificate)
        {
            UnidentifiedAccessKey = unidentifiedAccessKey;
            UnidentifiedCertificate = new SenderCertificate(unidentifiedCertificate);
        }

        public static byte[] DeriveAccessKeyFrom(byte[] profileKey)
        {
            byte[] nonce = new byte[12];
            byte[] input = new byte[16];
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(true, new AeadParameters(new KeyParameter(profileKey), 128, nonce));

            byte[] ciphertext = new byte[cipher.GetUpdateOutputSize(input.Length)];
            cipher.ProcessBytes(input, 0, input.Length, ciphertext, 0);

            byte[] tag = new byte[cipher.GetOutputSize(0)];
            cipher.DoFinal(tag, 0);

            byte[] combined = ByteUtil.combine(ciphertext, tag);
            return ByteUtil.trim(combined, 16);
        }
    }
}
