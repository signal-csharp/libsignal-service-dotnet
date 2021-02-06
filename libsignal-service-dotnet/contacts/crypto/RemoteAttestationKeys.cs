using libsignal.util;
using org.whispersystems.curve25519;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace libsignalservice.contacts.crypto
{
    internal class RemoteAttestationKeys
    {
        public byte[] ClientKey { get; } = new byte[32];
        public byte[] ServerKey { get; } = new byte[32];

        public RemoteAttestationKeys(Curve25519KeyPair keyPair, byte[] serverPublicEphemeral, byte[] serverPublicStatic)
        {
            byte[] ephemeralToEphemeral = Curve25519.getInstance(Curve25519.BEST).calculateAgreement(serverPublicEphemeral, keyPair.getPrivateKey());
            byte[] ephemeralToStatic = Curve25519.getInstance(Curve25519.BEST).calculateAgreement(serverPublicStatic, keyPair.getPrivateKey());

            byte[] masterSecret = ByteUtil.combine(ephemeralToEphemeral, ephemeralToStatic);
            byte[] publicKeys = ByteUtil.combine(keyPair.getPublicKey(), serverPublicEphemeral, serverPublicStatic);

            HkdfBytesGenerator generator = new HkdfBytesGenerator(new Sha256Digest());
            generator.Init(new HkdfParameters(masterSecret, publicKeys, null));
            generator.GenerateBytes(ClientKey, 0, ClientKey.Length);
            generator.GenerateBytes(ServerKey, 0, ServerKey.Length);
        }
    }
}
