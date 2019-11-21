using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using libsignal;
using libsignal.ecc;
using libsignal.exceptions;
using libsignal.kdf;
using libsignal.protocol;
using libsignal.state;
using libsignal.util;
using libsignalmetadata;
using libsignalmetadatadotnet.certificate;
using libsignalmetadatadotnet.protocol;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using TextSecure.libsignal;

namespace libsignalmetadatadotnet
{
    public class SealedSessionCipher
    {
        public SignalProtocolStore SignalProtocolStore { get; }
        public SignalProtocolAddress LocalAddress { get; }

        public SealedSessionCipher(SignalProtocolStore store, SignalProtocolAddress localAddress)
        {
            SignalProtocolStore = store;
            LocalAddress = localAddress;
        }

        public byte[] Encrypt(SignalProtocolAddress destinationAddress, SenderCertificate senderCertificate, byte[] paddedPlaintext)
        {
            CiphertextMessage message = new SessionCipher(SignalProtocolStore, destinationAddress).encrypt(paddedPlaintext);
            IdentityKeyPair ourIdentity = SignalProtocolStore.GetIdentityKeyPair();
            ECPublicKey theirIdentity = SignalProtocolStore.GetIdentity(destinationAddress).getPublicKey();

            ECKeyPair ephemeral = Curve.generateKeyPair();
            byte[] ephemeralSalt = ByteUtil.combine(Encoding.ASCII.GetBytes("UnidentifiedDelivery"), theirIdentity.serialize(), ephemeral.getPublicKey().serialize());
            EphemeralKeys ephemeralKeys = CalculateEphemeralKeys(theirIdentity, ephemeral.getPrivateKey(), ephemeralSalt);
            byte[] staticKeyCiphertext = Encrypt(ephemeralKeys.CipherKey, ephemeralKeys.MacKey, ourIdentity.getPublicKey().getPublicKey().serialize());

            byte[] staticSalt = ByteUtil.combine(ephemeralKeys.ChainKey, staticKeyCiphertext);
            StaticKeys staticKeys = CalculateStaticKeys(theirIdentity, ourIdentity.getPrivateKey(), staticSalt);
            UnidentifiedSenderMessageContent content = new UnidentifiedSenderMessageContent((int)message.getType(), senderCertificate, message.serialize());
            byte[] messageBytes = Encrypt(staticKeys.CipherKey, staticKeys.MacKey, content.Serialized);

            return new UnidentifiedSenderMessage(ephemeral.getPublicKey(), staticKeyCiphertext, messageBytes).Serialized;
        }

        public (SignalProtocolAddress, byte[]) Decrypt(CertificateValidator validator, byte[] ciphertext, long timestamp)
        {
            UnidentifiedSenderMessageContent content;

            try
            {
                IdentityKeyPair ourIdentity = SignalProtocolStore.GetIdentityKeyPair();
                UnidentifiedSenderMessage wrapper = new UnidentifiedSenderMessage(ciphertext);
                byte[] ephemeralSalt = ByteUtil.combine(Encoding.ASCII.GetBytes("UnidentifiedDelivery"), ourIdentity.getPublicKey().getPublicKey().serialize(), wrapper.Ephemeral.serialize());
                EphemeralKeys ephemeralKeys = CalculateEphemeralKeys(wrapper.Ephemeral, ourIdentity.getPrivateKey(), ephemeralSalt);
                byte[] staticKeyBytes = Decrypt(ephemeralKeys.CipherKey, ephemeralKeys.MacKey, wrapper.EncryptedStatic);

                ECPublicKey staticKey = Curve.decodePoint(staticKeyBytes, 0);
                byte[] staticSalt = ByteUtil.combine(ephemeralKeys.ChainKey, wrapper.EncryptedStatic);
                StaticKeys staticKeys = CalculateStaticKeys(staticKey, ourIdentity.getPrivateKey(), staticSalt);
                byte[] messageBytes = Decrypt(staticKeys.CipherKey, staticKeys.MacKey, wrapper.EncryptedMessage);

                content = new UnidentifiedSenderMessageContent(messageBytes);
                validator.Validate(content.SenderCertificate, timestamp);

                if (!Enumerable.SequenceEqual(content.SenderCertificate.Key.serialize(), staticKeyBytes))
                {
                    throw new libsignal.InvalidKeyException("Sender's certificate key does not match key used in message");
                }

                if (content.SenderCertificate.Sender == LocalAddress.Name &&
                    content.SenderCertificate.SenderDeviceId == LocalAddress.DeviceId)
                {
                    throw new SelfSendException();
                }
            }
            catch (libsignal.InvalidKeyException e)
            {
                throw new InvalidMetadataMessageException(e);
            }
            catch (InvalidCertificateException e)
            {
                throw new InvalidMetadataMessageException(e);
            }
            catch (InvalidMacException e)
            {
                throw new InvalidMetadataMessageException(e);
            }

            try
            {
                return (new SignalProtocolAddress(content.SenderCertificate.Sender, (uint)content.SenderCertificate.SenderDeviceId),
                    Decrypt(content));
            }
            catch (InvalidMessageException e)
            {
                throw new ProtocolInvalidMessageException(e, content.SenderCertificate.Sender, content.SenderCertificate.SenderDeviceId);
            }
            catch (libsignal.InvalidKeyException e)
            {
                throw new ProtocolInvalidKeyException(e, content.SenderCertificate.Sender, content.SenderCertificate.SenderDeviceId);
            }
            catch (NoSessionException e)
            {
                throw new ProtocolNoSessionException(e, content.SenderCertificate.Sender, content.SenderCertificate.SenderDeviceId);
            }
            catch (LegacyMessageException e)
            {
                throw new ProtocolLegacyMessageException(e, content.SenderCertificate.Sender, content.SenderCertificate.SenderDeviceId);
            }
            catch (InvalidVersionException e)
            {
                throw new ProtocolInvalidVersionException(e, content.SenderCertificate.Sender, content.SenderCertificate.SenderDeviceId);
            }
            catch (DuplicateMessageException e)
            {
                throw new ProtocolDuplicateMessageException(e, content.SenderCertificate.Sender, content.SenderCertificate.SenderDeviceId);
            }
            catch (InvalidKeyIdException e)
            {
                throw new ProtocolInvalidKeyIdException(e, content.SenderCertificate.Sender, content.SenderCertificate.SenderDeviceId);
            }
            catch (UntrustedIdentityException e)
            {
                throw new ProtocolUntrustedIdentityException(e, content.SenderCertificate.Sender, content.SenderCertificate.SenderDeviceId);
            }
        }

        public int GetSessionVersion(SignalProtocolAddress remoteAddress)
        {
            return (int)new SessionCipher(SignalProtocolStore, remoteAddress).getSessionVersion();
        }

        public int GetRemoteRegistrationId(SignalProtocolAddress remoteAddress)
        {
            return (int)new SessionCipher(SignalProtocolStore, remoteAddress).getRemoteRegistrationId();
        }

        private EphemeralKeys CalculateEphemeralKeys(ECPublicKey ephemeralPublic, ECPrivateKey ephemeralPrivate, byte[] salt)
        {
            byte[] ephemeralSecret = Curve.calculateAgreement(ephemeralPublic, ephemeralPrivate);
            byte[] ephemeralDerived = new HKDFv3().deriveSecrets(ephemeralSecret, salt, new byte[0], 96);
            byte[][] ephemeralDerivedParts = ByteUtil.split(ephemeralDerived, 32, 32, 32);

            return new EphemeralKeys(ephemeralDerivedParts[0], ephemeralDerivedParts[1], ephemeralDerivedParts[2]);
        }

        private StaticKeys CalculateStaticKeys(ECPublicKey staticPublic, ECPrivateKey staticPrivate, byte[] salt)
        {
            byte[] staticSecret = Curve.calculateAgreement(staticPublic, staticPrivate);
            byte[] staticDerived = new HKDFv3().deriveSecrets(staticSecret, salt, new byte[0], 96);
            byte[][] staticDerivedParts = ByteUtil.split(staticDerived, 32, 32, 32);

            return new StaticKeys(staticDerivedParts[1], staticDerivedParts[2]);
        }

        private byte[] Decrypt(UnidentifiedSenderMessageContent message)
        {
            SignalProtocolAddress sender = new SignalProtocolAddress(message.SenderCertificate.Sender, (uint)message.SenderCertificate.SenderDeviceId);

            switch ((uint)message.Type)
            {
                case CiphertextMessage.WHISPER_TYPE: return new SessionCipher(SignalProtocolStore, sender).decrypt(new SignalMessage(message.Content));
                case CiphertextMessage.PREKEY_TYPE: return new SessionCipher(SignalProtocolStore, sender).decrypt(new PreKeySignalMessage(message.Content));
                default: throw new InvalidMessageException("Unknown type: " + message.Type);
            }
        }

        private byte[] Encrypt(byte[] cipherKey, byte[] macKey, byte[] plaintext)
        {
            var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(true, new ParametersWithIV(new KeyParameter(cipherKey), new byte[16]));

            using var hmac = new HMACSHA256(macKey);
            byte[] ciphertext = cipher.DoFinal(plaintext);
            byte[] ourFullMac = hmac.ComputeHash(ciphertext);
            byte[] ourMac = ByteUtil.trim(ourFullMac, 10);

            return ByteUtil.combine(ciphertext, ourMac);
        }

        private byte[] Decrypt(byte[] cipherKey, byte[] macKey, byte[] ciphertext)
        {
            if (ciphertext.Length < 10)
            {
                throw new InvalidMacException("Ciphertext not long enough for MAC!");
            }

            byte[][] ciphertextParts = ByteUtil.split(ciphertext, ciphertext.Length - 10, 10);

            using var hmac = new HMACSHA256(macKey);
            byte[] digest = hmac.ComputeHash(ciphertextParts[0]);
            byte[] ourMac = ByteUtil.trim(digest, 10);
            byte[] theirMac = ciphertextParts[1];

            if (!Enumerable.SequenceEqual(ourMac, theirMac))
            {
                throw new InvalidMacException("Bad mac!");
            }

            var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(false, new ParametersWithIV(new KeyParameter(cipherKey), new byte[16]));
            return cipher.DoFinal(ciphertextParts[0]);
        }
    }

    internal class EphemeralKeys
    {
        public byte[] ChainKey { get; }
        public byte[] CipherKey { get; }
        public byte[] MacKey { get; }

        internal EphemeralKeys(byte[] chainKey, byte[] cipherKey, byte[] macKey)
        {
            this.ChainKey  = chainKey;
            this.CipherKey = cipherKey;
            this.MacKey    = macKey;
        }
    }

    internal class StaticKeys
    {
        public byte[] CipherKey { get; }
        public byte[] MacKey { get; }

        internal StaticKeys(byte[] cipherKey, byte[] macKey)
        {
            this.CipherKey = cipherKey;
            this.MacKey    = macKey;
        }
    }
}
