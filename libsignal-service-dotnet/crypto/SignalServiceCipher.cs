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
        private readonly CertificateValidator? certificateValidator;

        public SignalServiceCipher(SignalServiceAddress localAddress,
            SignalProtocolStore signalProtocolStore,
            CertificateValidator? certificateValidator)
        {
            this.signalProtocolStore = signalProtocolStore;
            this.localAddress = localAddress;
            this.certificateValidator = certificateValidator;
        }


        public OutgoingPushMessage Encrypt(SignalProtocolAddress destination, UnidentifiedAccess? unidentifiedAccess, byte[] unpaddedMessage)
        {
            if (unidentifiedAccess != null)
            {
                SealedSessionCipher sessionCipher = new SealedSessionCipher(signalProtocolStore, localAddress.Uuid, localAddress.GetNumber(), 1);
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
                byte[] paddedMessage;
                SignalServiceMetadata metadata;
                uint sessionVersion;

                if (!envelope.HasSource() && !envelope.IsUnidentifiedSender())
                {
                    throw new ProtocolInvalidMessageException(new InvalidMessageException("Non-UD envelope is missing a source!"), null, 0);
                }

                if (envelope.IsPreKeySignalMessage())
                {
                    SignalProtocolAddress sourceAddress = GetPreferredProtocolAddress(signalProtocolStore, envelope.GetSourceAddress(), envelope.GetSourceDevice());
                    SessionCipher sessionCipher = new SessionCipher(signalProtocolStore, sourceAddress);

                    paddedMessage = sessionCipher.decrypt(new PreKeySignalMessage(ciphertext));
                    metadata = new SignalServiceMetadata(envelope.GetSourceAddress(), envelope.GetSourceDevice(), envelope.GetTimestamp(), false);
                    sessionVersion = sessionCipher.getSessionVersion();
                }
                else if (envelope.IsSignalMessage())
                {
                    SignalProtocolAddress sourceAddress = GetPreferredProtocolAddress(signalProtocolStore, envelope.GetSourceAddress(), envelope.GetSourceDevice());
                    SessionCipher sessionCipher = new SessionCipher(signalProtocolStore, sourceAddress);

                    paddedMessage = sessionCipher.decrypt(new SignalMessage(ciphertext));
                    metadata       = new SignalServiceMetadata(envelope.GetSourceAddress(), envelope.GetSourceDevice(), envelope.GetTimestamp(), false);
                    sessionVersion = sessionCipher.getSessionVersion();
                }
                else if (envelope.IsUnidentifiedSender())
                {
                    SealedSessionCipher sealedSessionCipher = new SealedSessionCipher(signalProtocolStore, localAddress.Uuid, localAddress.GetNumber(), 1);
                    DecryptionResult result = sealedSessionCipher.Decrypt(certificateValidator!, ciphertext, (long)envelope.Envelope.ServerTimestamp);
                    SignalServiceAddress resultAddress = new SignalServiceAddress(UuidUtil.Parse(result.SenderUuid), result.SenderE164);
                    SignalProtocolAddress protocolAddress = GetPreferredProtocolAddress(signalProtocolStore, resultAddress, result.DeviceId);

                    paddedMessage = result.PaddedMessage;
                    metadata = new SignalServiceMetadata(resultAddress, result.DeviceId, envelope.GetTimestamp(), true);
                    sessionVersion = (uint)sealedSessionCipher.GetSessionVersion(protocolAddress);
                }
                else
                {
                    throw new InvalidMessageException($"Unknown type: {envelope.GetType()}");
                }

                PushTransportDetails transportDetails = new PushTransportDetails(sessionVersion);
                byte[] data = transportDetails.GetStrippedPaddingMessageBody(paddedMessage);

                return new Plaintext(metadata, data);
            }
            catch (DuplicateMessageException e)
            {
                throw new ProtocolDuplicateMessageException(e, envelope.GetSourceIdentifier(), envelope.GetSourceDevice());
            }
            catch (LegacyMessageException e)
            {
                throw new ProtocolLegacyMessageException(e, envelope.GetSourceIdentifier(), envelope.GetSourceDevice());
            }
            catch (InvalidMessageException e)
            {
                throw new ProtocolInvalidMessageException(e, envelope.GetSourceIdentifier(), envelope.GetSourceDevice());
            }
            catch (InvalidKeyIdException e)
            {
                throw new ProtocolInvalidKeyIdException(e, envelope.GetSourceIdentifier(), envelope.GetSourceDevice());
            }
            catch (InvalidKeyException e)
            {
                throw new ProtocolInvalidKeyException(e, envelope.GetSourceIdentifier(), envelope.GetSourceDevice());
            }
            catch (libsignal.exceptions.UntrustedIdentityException e)
            {
                throw new ProtocolUntrustedIdentityException(e, envelope.GetSourceIdentifier(), envelope.GetSourceDevice());
            }
            catch (InvalidVersionException e)
            {
                throw new ProtocolInvalidVersionException(e, envelope.GetSourceIdentifier(), envelope.GetSourceDevice());
            }
            catch (NoSessionException e)
            {
                throw new ProtocolNoSessionException(e, envelope.GetSourceIdentifier(), envelope.GetSourceDevice());
            }
        }

        private static SignalProtocolAddress GetPreferredProtocolAddress(SignalProtocolStore store, SignalServiceAddress address, int sourceDevice)
        {
            SignalProtocolAddress? uuidAddress = address.Uuid.HasValue ? new SignalProtocolAddress(address.Uuid.Value.ToString(), (uint)sourceDevice) : null;
            SignalProtocolAddress? e164Address = address.GetNumber() != null ? new SignalProtocolAddress(address.GetNumber(), (uint)sourceDevice) : null;

            if (uuidAddress != null && store.ContainsSession(uuidAddress))
            {
                return uuidAddress;
            }
            else if (e164Address != null && store.ContainsSession(e164Address))
            {
                return e164Address;
            }
            else
            {
                return new SignalProtocolAddress(address.GetIdentifier(), (uint)sourceDevice);
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
