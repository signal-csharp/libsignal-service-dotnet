using System;
using System.Collections.Generic;
using System.Linq;
using Google.Protobuf;
using libsignal;
using libsignal.messages.multidevice;
using libsignal.protocol;
using libsignal.state;
using libsignal_service_dotnet.messages.calls;
using libsignalmetadata;
using libsignalmetadatadotnet;
using libsignalmetadatadotnet.certificate;
using libsignalservice.messages;
using libsignalservice.messages.multidevice;
using libsignalservice.messages.shared;
using libsignalservice.push;
using libsignalservice.serialize;
using libsignalservice.util;
using libsignalservicedotnet.crypto;
using serialize.protos;

namespace libsignalservice.crypto
{
    /// <summary>
    /// This is used to decrypt received <see cref="SignalServiceEnvelope"/>s
    /// </summary>
    public class SignalServiceCipher
    {
        private readonly SignalProtocolStore signalProtocolStore;
        private readonly SignalServiceAddress localAddress;
        private readonly CertificateValidator certificateValidator;

        public SignalServiceCipher(SignalServiceAddress localAddress,
            SignalProtocolStore signalProtocolStore,
            CertificateValidator certificateValidator)
        {
            this.signalProtocolStore = signalProtocolStore;
            this.localAddress = localAddress;
            this.certificateValidator = certificateValidator;
        }


        public OutgoingPushMessage Encrypt(SignalProtocolAddress destination, UnidentifiedAccess unidentifiedAccess, byte[] unpaddedMessage)
        {
            if (unidentifiedAccess != null)
            {
                SealedSessionCipher sessionCipher = new SealedSessionCipher(signalProtocolStore, new SignalProtocolAddress(localAddress.E164number, 1));
                PushTransportDetails transportDetails = new PushTransportDetails((uint)sessionCipher.GetSessionVersion(destination));
                byte[] ciphertext = sessionCipher.Encrypt(destination, unidentifiedAccess.UnidentifiedCertificate, transportDetails.getPaddedMessageBody(unpaddedMessage));
                string body = Base64.EncodeBytes(ciphertext);
                uint remoteRegistrationId = (uint)sessionCipher.GetRemoteRegistrationId(destination);
                return new OutgoingPushMessage((uint)Envelope.Types.Type.UnidentifiedSender, destination.DeviceId, remoteRegistrationId, body);
            }
            else
            {
                SessionCipher sessionCipher = new SessionCipher(signalProtocolStore, destination);
                PushTransportDetails transportDetails = new PushTransportDetails(sessionCipher.getSessionVersion());
                CiphertextMessage message = sessionCipher.encrypt(transportDetails.getPaddedMessageBody(unpaddedMessage));
                uint remoteRegistrationId = sessionCipher.getRemoteRegistrationId();
                string body = Base64.EncodeBytes(message.serialize());

                var type = (message.getType()) switch
                {
                    CiphertextMessage.PREKEY_TYPE => (uint)Envelope.Types.Type.PrekeyBundle,
                    CiphertextMessage.WHISPER_TYPE => (uint)Envelope.Types.Type.Ciphertext,
                    _ => throw new Exception("Bad type: " + message.getType()),
                };
                return new OutgoingPushMessage(type, destination.DeviceId, remoteRegistrationId, body);
            }
        }

        /// <summary>
        /// Decrypt a received <see cref="SignalServiceEnvelope"/>
        /// </summary>
        /// <param name="envelope">The received SignalServiceEnvelope</param>
        /// <returns>a decrypted SignalServiceContent</returns>
        public SignalServiceContent? Decrypt(SignalServiceEnvelope envelope)
        {
            try
            {
                if (envelope.HasLegacyMessage())
                {
                    Plaintext plaintext = Decrypt(envelope, envelope.GetLegacyMessage());
                    DataMessage dataMessage = DataMessage.Parser.ParseFrom(plaintext.data);

                    SignalServiceContentProto contentProto = new SignalServiceContentProto()
                    {
                        LocalAddress = SignalServiceAddressProtobufSerializer.ToProtobuf(localAddress),
                        Metadata = SignalServiceMetadataProtobufSerializer.ToProtobuf(plaintext.Metadata),
                        LegacyDataMessage = dataMessage
                    };

                    return SignalServiceContent.CreateFromProto(contentProto);
                }
                else if (envelope.HasContent())
                {
                    Plaintext plaintext = Decrypt(envelope, envelope.Envelope.Content.ToByteArray());
                    Content content = Content.Parser.ParseFrom(plaintext.data);

                    SignalServiceContentProto contentProto = new SignalServiceContentProto()
                    {
                        LocalAddress = SignalServiceAddressProtobufSerializer.ToProtobuf(localAddress),
                        Metadata = SignalServiceMetadataProtobufSerializer.ToProtobuf(plaintext.Metadata),
                        Content = content
                    };

                    return SignalServiceContent.CreateFromProto(contentProto);
                }
                return null;
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidMetadataMessageException(e);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="envelope"></param>
        /// <param name="ciphertext"></param>
        /// <returns></returns>
        /// <exception cref="InvalidMetadataMessageException"></exception>
        /// <exception cref="InvalidMetadataVersionException"></exception>
        /// <exception cref="ProtocolDuplicateMessageException"></exception>
        /// <exception cref="ProtocolUntrustedIdentityException"></exception>
        /// <exception cref="ProtocolLegacyMessageException"></exception>
        /// <exception cref="ProtocolInvalidKeyException"></exception>
        /// <exception cref="ProtocolInvalidVersionException"></exception>
        /// <exception cref="ProtocolInvalidMessageException"></exception>
        /// <exception cref="ProtocolInvalidKeyIdException"></exception>
        /// <exception cref="ProtocolNoSessionException"></exception>
        /// <exception cref="SelfSendException"></exception>
        private Plaintext Decrypt(SignalServiceEnvelope envelope, byte[] ciphertext)
        {
            try
            {
                SignalProtocolAddress sourceAddress = new SignalProtocolAddress(envelope.GetSource(), (uint)envelope.GetSourceDevice());
                SessionCipher sessionCipher = new SessionCipher(signalProtocolStore, sourceAddress);
                SealedSessionCipher sealedSessionCipher = new SealedSessionCipher(signalProtocolStore, new SignalProtocolAddress(localAddress.E164number, 1));

                byte[] paddedMessage;
                SignalServiceMetadata metadata;
                uint sessionVersion;

                if (envelope.IsPreKeySignalMessage())
                {
                    paddedMessage = sessionCipher.decrypt(new PreKeySignalMessage(ciphertext));
                    metadata       = new SignalServiceMetadata(envelope.GetSourceAddress(), envelope.GetSourceDevice(), envelope.GetTimestamp(), false);
                    sessionVersion = sessionCipher.getSessionVersion();
                }
                else if (envelope.IsSignalMessage())
                {
                    paddedMessage = sessionCipher.decrypt(new SignalMessage(ciphertext));
                    metadata       = new SignalServiceMetadata(envelope.GetSourceAddress(), envelope.GetSourceDevice(), envelope.GetTimestamp(), false);
                    sessionVersion = sessionCipher.getSessionVersion();
                }
                else if (envelope.IsUnidentifiedSender())
                {
                    var results = sealedSessionCipher.Decrypt(certificateValidator, ciphertext, (long)envelope.Envelope.ServerTimestamp);
                    paddedMessage = results.Item2;
                    // TODO: STOPPED HERE
                    metadata = new SignalServiceMetadata(results.Item1.Name, (int) results.Item1.DeviceId, (long) envelope.Envelope.Timestamp, true);
                    sessionVersion = (uint) sealedSessionCipher.GetSessionVersion(new SignalProtocolAddress(metadata.Sender, (uint) metadata.SenderDevice));
                }
                else
                {
                    throw new InvalidMessageException("Unknown type: " + envelope.GetEnvelopeType() + " from " + envelope.GetSource());
                }

                PushTransportDetails transportDetails = new PushTransportDetails(sessionVersion);
                byte[] data = transportDetails.GetStrippedPaddingMessageBody(paddedMessage);
                return new Plaintext(metadata, data);
            }
            catch (DuplicateMessageException e)
            {
                throw new ProtocolDuplicateMessageException(e, envelope.GetSource(), envelope.GetSourceDevice());
            }
            catch (LegacyMessageException e)
            {
                throw new ProtocolLegacyMessageException(e, envelope.GetSource(), envelope.GetSourceDevice());
            }
            catch (InvalidMessageException e)
            {
                throw new ProtocolInvalidMessageException(e, envelope.GetSource(), envelope.GetSourceDevice());
            }
            catch (InvalidKeyIdException e)
            {
                throw new ProtocolInvalidKeyIdException(e, envelope.GetSource(), envelope.GetSourceDevice());
            }
            catch (InvalidKeyException e)
            {
                throw new ProtocolInvalidKeyException(e, envelope.GetSource(), envelope.GetSourceDevice());
            }
            catch (libsignal.exceptions.UntrustedIdentityException e)
            {
                throw new ProtocolUntrustedIdentityException(e, envelope.GetSource(), envelope.GetSourceDevice());
            }
            catch (InvalidVersionException e)
            {
                throw new ProtocolInvalidVersionException(e, envelope.GetSource(), envelope.GetSourceDevice());
            }
            catch (NoSessionException e)
            {
                throw new ProtocolNoSessionException(e, envelope.GetSource(), envelope.GetSourceDevice());
            }
        }
    }

    internal class Plaintext
    {
        public SignalServiceMetadata Metadata { get; }
        public readonly byte[] data;

        public Plaintext(SignalServiceMetadata metadata, byte[] data)
        {
            Metadata = metadata;
            this.data     = data;
        }
    }
}
