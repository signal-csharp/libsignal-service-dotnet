using System;
using System.Collections.Generic;
using System.Text;
using Google.Protobuf;
using libsignal.protocol;
using libsignalmetadata;
using libsignalmetadatadotnet.certificate;

namespace libsignalmetadatadotnet.protocol
{
    public class UnidentifiedSenderMessageContent
    {
        public int Type { get; }
        public SenderCertificate SenderCertificate { get; }
        public byte[] Content { get; }
        public byte[] Serialized { get; }

        public UnidentifiedSenderMessageContent(byte[] serialized)
        {
            try
            {
                var message = libsignalmetadata.protobuf.UnidentifiedSenderMessage.Types.Message.Parser.ParseFrom(serialized);

                if (message.TypeOneofCase != libsignalmetadata.protobuf.UnidentifiedSenderMessage.Types.Message.TypeOneofOneofCase.Type ||
                    message.SenderCertificateOneofCase != libsignalmetadata.protobuf.UnidentifiedSenderMessage.Types.Message.SenderCertificateOneofOneofCase.SenderCertificate ||
                    message.ContentOneofCase != libsignalmetadata.protobuf.UnidentifiedSenderMessage.Types.Message.ContentOneofOneofCase.Content)
                {
                    throw new InvalidMetadataMessageException("Missing fields");
                }

                switch (message.Type)
                {
                    case libsignalmetadata.protobuf.UnidentifiedSenderMessage.Types.Message.Types.Type.Message: Type = (int)CiphertextMessage.WHISPER_TYPE; break;
                    case libsignalmetadata.protobuf.UnidentifiedSenderMessage.Types.Message.Types.Type.PrekeyMessage: Type = (int)CiphertextMessage.PREKEY_TYPE; break;
                    default: throw new InvalidMetadataMessageException("Unknown type: " + message.Type);
                }

                SenderCertificate = new SenderCertificate(message.SenderCertificate.ToByteArray());
                Content           = message.Content.ToByteArray();
                Serialized        = serialized;
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidMetadataMessageException(e);
            }
        }

        public UnidentifiedSenderMessageContent(int type, SenderCertificate senderCertificate, byte[] content)
        {
            Serialized = new libsignalmetadata.protobuf.UnidentifiedSenderMessage.Types.Message()
            {
                Type = (libsignalmetadata.protobuf.UnidentifiedSenderMessage.Types.Message.Types.Type)GetProtoType(type),
                SenderCertificate = libsignalmetadata.protobuf.SenderCertificate.Parser.ParseFrom(senderCertificate.Serialized),
                Content = ByteString.CopyFrom(content)
            }.ToByteArray();

            Type = type;
            SenderCertificate = senderCertificate;
            Content = content;
        }

        private int GetProtoType(int type)
        {
            switch ((uint) type)
            {
                case CiphertextMessage.WHISPER_TYPE: return (int) libsignalmetadata.protobuf.UnidentifiedSenderMessage.Types.Message.Types.Type.Message;
                case CiphertextMessage.PREKEY_TYPE: return (int)libsignalmetadata.protobuf.UnidentifiedSenderMessage.Types.Message.Types.Type.PrekeyMessage;
                default: throw new Exception($"GetProtoType failed: Unknown type {type}");
            }
        }
    }
}
