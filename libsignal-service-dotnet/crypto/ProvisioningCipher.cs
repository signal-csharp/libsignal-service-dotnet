using Google.Protobuf;
using libsignal;
using libsignal.ecc;
using libsignal.kdf;
using libsignalservice.push;
using libsignalservice.util;

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace libsignalservice.crypto
{
    internal class ProvisioningCipher
    {
        private readonly ECPublicKey theirPublicKey;

        public ProvisioningCipher(ECPublicKey theirPublicKey)
        {
            this.theirPublicKey = theirPublicKey;
        }

        public ProvisionMessage Decrypt(IdentityKeyPair tmpIdentity, byte[] message)
        {
            ProvisionEnvelope env = ProvisionEnvelope.Parser.ParseFrom(message);
            ECPublicKey publicKey = Curve.decodePoint(env.PublicKey.ToByteArray(), 0);
            byte[] sharedSecret = Curve.calculateAgreement(publicKey, tmpIdentity.getPrivateKey());
            byte[] derivedSecret = new HKDFv3().deriveSecrets(sharedSecret, Encoding.UTF8.GetBytes("TextSecure Provisioning Message"), 64);
            byte[][] parts = Util.Split(derivedSecret, 32, 32);
            byte[] joined = env.Body.ToByteArray();
            if (joined[0] != 0x01)
            {
                throw new Exception("Bad version number on provision message!");
            }
            byte[] iv = new byte[16];
            Array.Copy(joined, 1, iv, 0, 16);
            byte[] ciphertext = new byte[joined.Length - 32 - 17];
            Array.Copy(joined, 17, ciphertext, 0, joined.Length - 32 - 17);
            byte[] ivAndCiphertext = new byte[joined.Length - 32];
            Array.Copy(joined, ivAndCiphertext, joined.Length - 32);
            byte[] mac = new byte[32];
            Array.Copy(joined, joined.Length - 32, mac, 0, 32);

            verifyMac(parts[1], ivAndCiphertext, mac);
            return ProvisionMessage.Parser.ParseFrom(Decrypt(parts[0], iv, ciphertext));
        }

        private void verifyMac(byte[] key, byte[] message, byte[] theirMac)
        {
            byte[] ourMac = getMac(key, message);
            if (!ourMac.SequenceEqual(theirMac))
            {
                throw new Exception("Invalid MAC on provision message!");
            }
        }

        private byte[] Decrypt(byte[] key, byte[] iv, byte[] ciphertext)
        {
            using (var aes = Aes.Create())
            {
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;
                using (var dec = aes.CreateDecryptor())
                using (var from = new MemoryStream(ciphertext))
                using (var reader = new CryptoStream(from, dec, CryptoStreamMode.Read))
                using (var target = new MemoryStream())
                {
                    reader.CopyTo(target);
                    return target.ToArray();
                }
            }
        }

        public byte[] encrypt(ProvisionMessage message)// throws InvalidKeyException
        {
            ECKeyPair ourKeyPair = Curve.generateKeyPair();
            byte[] sharedSecret = Curve.calculateAgreement(theirPublicKey, ourKeyPair.getPrivateKey());
            byte[] derivedSecret = new HKDFv3().deriveSecrets(sharedSecret, Encoding.UTF8.GetBytes("TextSecure Provisioning Message"), 64);
            byte[][] parts = Util.Split(derivedSecret, 32, 32);

            byte[] version = { 0x01 };
            byte[] ciphertext = getCiphertext(parts[0], message.ToByteArray());
            byte[] mac = getMac(parts[1], Util.Join(version, ciphertext));
            byte[] body = Util.Join(version, ciphertext, mac);

            return new ProvisionEnvelope
            {
                PublicKey = ByteString.CopyFrom(ourKeyPair.getPublicKey().serialize()),
                Body = ByteString.CopyFrom(body)
            }.ToByteArray();
        }

        private byte[] getCiphertext(byte[] key, byte[] message)
        {
            try
            {
                using (var aes = Aes.Create())
                using (var enc = aes.CreateEncryptor())
                {
                    aes.BlockSize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = key;
                    return Util.Join(aes.IV, enc.TransformFinalBlock(message, 0, message.Length));
                }
            }
            catch (/*NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException | IllegalBlockSizeException | BadPaddingException*/ Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        private byte[] getMac(byte[] key, byte[] message)
        {
            try
            {
                HMACSHA256 mac = new HMACSHA256();
                mac.Key = key;
                return mac.ComputeHash(message);
            }
            catch (/*NoSuchAlgorithmException | java.security.InvalidKeyException*/Exception e)
            {
                throw new Exception(e.Message);
            }
        }
    }
}
