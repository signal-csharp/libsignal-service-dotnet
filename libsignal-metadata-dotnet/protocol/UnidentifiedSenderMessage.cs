using System;
using System.Collections.Generic;
using System.Text;
using Google.Protobuf;
using libsignal;
using libsignal.ecc;
using libsignal.util;
using libsignalmetadata;
using static libsignalmetadata.protobuf.UnidentifiedSenderMessage;

namespace libsignalmetadatadotnet.protocol
{
    public class UnidentifiedSenderMessage
    {
        private static readonly int CIPHERTEXT_VERSION = 1;

        public int Version { get; }
        public ECPublicKey Ephemeral { get; }
        public byte[] EncryptedStatic { get; }
        public byte[] EncryptedMessage { get; }
        public byte[] Serialized { get; }

        public UnidentifiedSenderMessage(byte[] serialized)
        {
            try
            {
                Version = ByteUtil.highBitsToInt(serialized[0]);
                if (Version > CIPHERTEXT_VERSION)
                {
                    throw new InvalidMetadataVersionException("Unknown version: " + Version);
                }

                var unidentifiedSenderMessage = Parser.ParseFrom(ByteString.CopyFrom(serialized, 1, serialized.Length - 1));

                if (unidentifiedSenderMessage.EphemeralPublicOneofCase != EphemeralPublicOneofOneofCase.EphemeralPublic ||
                    unidentifiedSenderMessage.EncryptedStaticOneofCase != EncryptedStaticOneofOneofCase.EncryptedStatic ||
                    unidentifiedSenderMessage.EncryptedMessageOneofCase != EncryptedMessageOneofOneofCase.EncryptedMessage)
                {
                    throw new InvalidMetadataMessageException("Missing fields");
                }

                Ephemeral        = Curve.decodePoint(unidentifiedSenderMessage.EphemeralPublic.ToByteArray(), 0);
                EncryptedStatic  = unidentifiedSenderMessage.EncryptedStatic.ToByteArray();
                EncryptedMessage = unidentifiedSenderMessage.EncryptedMessage.ToByteArray();
                Serialized       = serialized;
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidMetadataMessageException(e);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidMetadataMessageException(e);
            }
        }

        public UnidentifiedSenderMessage(ECPublicKey ephemeral, byte[] encryptedStatic, byte[] encryptedMessage)
        {
            Version          = CIPHERTEXT_VERSION;
            Ephemeral        = ephemeral;
            EncryptedStatic  = encryptedStatic;
            EncryptedMessage = encryptedMessage;

            byte[] versionBytes = { ByteUtil.intsToByteHighAndLow(CIPHERTEXT_VERSION, CIPHERTEXT_VERSION) };
            byte[] messageBytes = new libsignalmetadata.protobuf.UnidentifiedSenderMessage()
            {
                EncryptedMessage = ByteString.CopyFrom(encryptedMessage),
                EncryptedStatic = ByteString.CopyFrom(encryptedStatic),
                EphemeralPublic = ByteString.CopyFrom(ephemeral.serialize())
            }.ToByteArray();
            this.Serialized = ByteUtil.combine(versionBytes, messageBytes);
        }
    }
}
