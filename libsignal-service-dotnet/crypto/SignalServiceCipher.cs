using Google.Protobuf;
using libsignal;
using libsignal.protocol;
using libsignal.state;
using libsignal_service_dotnet.messages.calls;
using libsignalservice.messages;
using libsignalservice.messages.multidevice;
using libsignalservice.push;
using libsignalservice.util;

using System;
using System.Collections.Generic;

namespace libsignalservice.crypto
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    /// <summary>
    /// This is used to decrypt received <see cref="SignalServiceEnvelope"/>s
    /// </summary>
    public class SignalServiceCipher
    {
        private readonly SignalProtocolStore SignalProtocolStore;
        private readonly SignalServiceAddress LocalAddress;

        public SignalServiceCipher(SignalServiceAddress localAddress, SignalProtocolStore signalProtocolStore)
        {
            this.SignalProtocolStore = signalProtocolStore;
            this.LocalAddress = localAddress;
        }


        public OutgoingPushMessage Encrypt(SignalProtocolAddress destination, byte[] unpaddedMessage, bool silent)
        {
            SessionCipher sessionCipher = new SessionCipher(SignalProtocolStore, destination);
            PushTransportDetails transportDetails = new PushTransportDetails(sessionCipher.getSessionVersion());
            CiphertextMessage message = sessionCipher.encrypt(transportDetails.getPaddedMessageBody(unpaddedMessage));
            uint remoteRegistrationId = sessionCipher.getRemoteRegistrationId();
            String body = Base64.EncodeBytes(message.serialize());

            uint type;

            switch (message.getType())
            {
                case CiphertextMessage.PREKEY_TYPE: type = (uint)Envelope.Types.Type.PrekeyBundle; break; // todo check
                case CiphertextMessage.WHISPER_TYPE: type = (uint)Envelope.Types.Type.Ciphertext; break; // todo check
                default: throw new Exception("Bad type: " + message.getType());
            }

            return new OutgoingPushMessage(type, destination.DeviceId, remoteRegistrationId, body, silent);
        }

        /// <summary>
        /// Decrypt a received <see cref="SignalServiceEnvelope"/>
        /// </summary>
        /// <param name="envelope">The received SignalServiceEnvelope</param>
        /// <returns>a decrypted SignalServiceContent</returns>
        public SignalServiceContent Decrypt(SignalServiceEnvelope envelope)
        {
            try
            {
                SignalServiceContent content = new SignalServiceContent();

                if (envelope.hasLegacyMessage())
                {
                    DataMessage message = DataMessage.Parser.ParseFrom(Decrypt(envelope, envelope.getLegacyMessage()));
                    content = new SignalServiceContent()
                    {
                        Message = CreateSignalServiceMessage(envelope, message)
                    };
                }
                else if (envelope.hasContent())
                {
                    Content message = Content.Parser.ParseFrom(Decrypt(envelope, envelope.getContent()));

                    if (message.DataMessageOneofCase == Content.DataMessageOneofOneofCase.DataMessage)
                    {
                        content = new SignalServiceContent()
                        {
                            Message = CreateSignalServiceMessage(envelope, message.DataMessage)
                        };
                    }
                    else if (message.SyncMessageOneofCase == Content.SyncMessageOneofOneofCase.SyncMessage && LocalAddress.E164number == envelope.getSource())
                    {
                        content = new SignalServiceContent()
                        {
                            SynchronizeMessage = CreateSynchronizeMessage(envelope, message.SyncMessage)
                        };
                    }
                    else if (message.CallMessageOneofCase == Content.CallMessageOneofOneofCase.CallMessage)
                    {
                        content = new SignalServiceContent()
                        {
                            CallMessage = CreateCallMessage(message.CallMessage)
                        };
                    }
                    else if (message.ReceiptMessageOneofCase == Content.ReceiptMessageOneofOneofCase.ReceiptMessage)
                    {
                        content = new SignalServiceContent()
                        {
                            ReadMessage = createReceiptMessage(envelope, message.ReceiptMessage)
                        };
                    }
                }

                return content;
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidMessageException(e);
            }
        }

        private byte[] Decrypt(SignalServiceEnvelope envelope, byte[] ciphertext)

        {
            SignalProtocolAddress sourceAddress = new SignalProtocolAddress(envelope.getSource(), (uint)envelope.getSourceDevice());
            SessionCipher sessionCipher = new SessionCipher(SignalProtocolStore, sourceAddress);

            byte[] paddedMessage;

            if (envelope.isPreKeySignalMessage())
            {
                paddedMessage = sessionCipher.decrypt(new PreKeySignalMessage(ciphertext));
            }
            else if (envelope.isSignalMessage())
            {
                paddedMessage = sessionCipher.decrypt(new SignalMessage(ciphertext));
            }
            else
            {
                throw new InvalidMessageException("Unknown type: " + envelope.getType() + " from " + envelope.getSource());
            }

            PushTransportDetails transportDetails = new PushTransportDetails(sessionCipher.getSessionVersion());
            return transportDetails.getStrippedPaddingMessageBody(paddedMessage);
        }

        private SignalServiceDataMessage CreateSignalServiceMessage(SignalServiceEnvelope envelope, DataMessage content)
        {
            SignalServiceGroup groupInfo = CreateGroupInfo(envelope, content);
            List<SignalServiceAttachment> attachments = new List<SignalServiceAttachment>();
            bool endSession = ((content.Flags & (uint)DataMessage.Types.Flags.EndSession) != 0);
            bool expirationUpdate = ((content.Flags & (uint)DataMessage.Types.Flags.ExpirationTimerUpdate) != 0);
            bool profileKeyUpdate = ((content.Flags & (uint)DataMessage.Types.Flags.ProfileKeyUpdate) != 0);

            foreach (AttachmentPointer pointer in content.Attachments)
            {
                attachments.Add(new SignalServiceAttachmentPointer(pointer.Id,
                                                                pointer.ContentType,
                                                                pointer.Key.ToByteArray(),
                                                                envelope.getRelay(),
                                                                pointer.SizeOneofCase == AttachmentPointer.SizeOneofOneofCase.Size ? pointer.Size : 0,
                                                                pointer.ThumbnailOneofCase == AttachmentPointer.ThumbnailOneofOneofCase.Thumbnail ? pointer.Thumbnail.ToByteArray() : null,
                                                                pointer.DigestOneofCase == AttachmentPointer.DigestOneofOneofCase.Digest ? pointer.Digest.ToByteArray() : null,
                                                                pointer.FileNameOneofCase == AttachmentPointer.FileNameOneofOneofCase.FileName ? pointer.FileName : null,
                                                                pointer.FlagsOneofCase == AttachmentPointer.FlagsOneofOneofCase.Flags && (pointer.Flags & (uint) AttachmentPointer.Types.Flags.VoiceMessage) != 0));
            }

            return new SignalServiceDataMessage()
            {
                Timestamp = envelope.getTimestamp(),
                Group = groupInfo,
                Attachments = attachments,
                Body = content.Body,
                EndSession = endSession,
                ExpiresInSeconds = (int)content.ExpireTimer,
                ExpirationUpdate = expirationUpdate,
                ProfileKey = content.ProfileKeyOneofCase == DataMessage.ProfileKeyOneofOneofCase.ProfileKey ? content.ProfileKey.ToByteArray() : null,
                ProfileKeyUpdate = profileKeyUpdate
            };
        }

        private SignalServiceSyncMessage CreateSynchronizeMessage(SignalServiceEnvelope envelope, SyncMessage content)
        {
            if (content.SentOneofCase == SyncMessage.SentOneofOneofCase.Sent)
            {
                SyncMessage.Types.Sent sentContent = content.Sent;
                return SignalServiceSyncMessage.ForSentTranscript(new SentTranscriptMessage(sentContent.Destination,
                                                                           (long)sentContent.Timestamp,
                                                                           CreateSignalServiceMessage(envelope, sentContent.Message),
                                                                           (long)sentContent.ExpirationStartTimestamp));
            }

            if (content.RequestOneofCase == SyncMessage.RequestOneofOneofCase.Request)
            {
                return SignalServiceSyncMessage.ForRequest(new RequestMessage(content.Request));
            }

            if (content.Read.Count > 0)
            {
                List<ReadMessage> readMessages = new List<ReadMessage>();

                foreach (SyncMessage.Types.Read read in content.Read)
                {
                    readMessages.Add(new ReadMessage(read.Sender, (long)read.Timestamp));
                }

                return SignalServiceSyncMessage.ForRead(readMessages);
            }

            if (content.VerifiedOneofCase == SyncMessage.VerifiedOneofOneofCase.Verified)
            {
                try
                {
                    Verified verified = content.Verified;
                    string destination = verified.Destination;
                    IdentityKey identityKey = new IdentityKey(verified.IdentityKey.ToByteArray(), 0);

                    VerifiedMessage.VerifiedState verifiedState;

                    if (verified.State == Verified.Types.State.Default)
                    {
                        verifiedState = VerifiedMessage.VerifiedState.Default;
                    }
                    else if (verified.State == Verified.Types.State.Verified)
                    {
                        verifiedState = VerifiedMessage.VerifiedState.Verified;
                    }
                    else if (verified.State == Verified.Types.State.Unverified)
                    {
                        verifiedState = VerifiedMessage.VerifiedState.Unverified;
                    }
                    else
                    {
                        throw new InvalidMessageException("Unknown state: " + verified.State);
                    }

                    return SignalServiceSyncMessage.ForVerified(new VerifiedMessage(destination, identityKey, verifiedState, Util.CurrentTimeMillis()));
                }
                catch (InvalidKeyException e)
                {
                    throw new InvalidMessageException(e);
                }
            }

            return SignalServiceSyncMessage.Empty();
        }

        private SignalServiceCallMessage CreateCallMessage(CallMessage content)
        {
            if (content.OfferOneofCase == CallMessage.OfferOneofOneofCase.Offer)
            {
                return new SignalServiceCallMessage()
                {
                    OfferMessage = new OfferMessage()
                    {
                        Id = content.Offer.Id,
                        Description = content.Offer.Description
                    }
                };
            }
            else if (content.AnswerOneofCase == CallMessage.AnswerOneofOneofCase.Answer)
            {
                return new SignalServiceCallMessage()
                {
                    AnswerMessage = new AnswerMessage()
                    {
                        Id = content.Answer.Id,
                        Description = content.Answer.Description
                    }
                };
            }
            else if (content.IceUpdate.Count > 0)
            {
                var m = new SignalServiceCallMessage();
                var l = new List<IceUpdateMessage>();
                foreach (var u in content.IceUpdate)
                {
                   l.Add(new IceUpdateMessage()
                    {
                        Id = u.Id,
                        SdpMid = u.SdpMid,
                        SdpMLineIndex = u.SdpMLineIndex,
                        Sdp = u.Sdp
                    });
                }
                m.IceUpdateMessages = l;
                return m;
            }
            else if (content.HangupOneofCase == CallMessage.HangupOneofOneofCase.Hangup)
            {
                return new SignalServiceCallMessage()
                {
                    HangupMessage = new HangupMessage()
                    {
                        Id = content.Hangup.Id,
                    }
                };
            }
            else if (content.BusyOneofCase == CallMessage.BusyOneofOneofCase.Busy)
            {
                return new SignalServiceCallMessage()
                {
                    BusyMessage = new BusyMessage()
                    {
                        Id = content.Busy.Id
                    }
                };
            }
            return new SignalServiceCallMessage();
        }

        private SignalServiceReceiptMessage createReceiptMessage(SignalServiceEnvelope envelope, ReceiptMessage content)
        {
            SignalServiceReceiptMessage.Type type;

            if (content.TypeOneofCase == ReceiptMessage.TypeOneofOneofCase.Type)
            {
                if (content.Type == ReceiptMessage.Types.Type.Delivery)
                {
                    type = SignalServiceReceiptMessage.Type.DELIVERY;
                }
                else if (content.Type == ReceiptMessage.Types.Type.Read)
                {
                    type = SignalServiceReceiptMessage.Type.READ;
                }
                else
                {
                    type = SignalServiceReceiptMessage.Type.UNKNOWN;
                }
            }
            else
            {
                type = SignalServiceReceiptMessage.Type.UNKNOWN;
            }
            var timestamps = new List<ulong>();
            foreach (var timestamp in content.Timestamp)
            {
                timestamps.Add(timestamp);
            }
            return new SignalServiceReceiptMessage()
            {
                ReceiptType = type,
                Timestamps = timestamps,
                When = envelope.getTimestamp()
            };
        }

        private SignalServiceGroup CreateGroupInfo(SignalServiceEnvelope envelope, DataMessage content)
        {
            if (content.GroupOneofCase == DataMessage.GroupOneofOneofCase.None) return null;

            SignalServiceGroup.GroupType type;

            switch (content.Group.Type)
            {
                case GroupContext.Types.Type.Deliver: type = SignalServiceGroup.GroupType.DELIVER; break;
                case GroupContext.Types.Type.Update: type = SignalServiceGroup.GroupType.UPDATE; break;
                case GroupContext.Types.Type.Quit: type = SignalServiceGroup.GroupType.QUIT; break;
                case GroupContext.Types.Type.RequestInfo: type = SignalServiceGroup.GroupType.REQUEST_INFO; break;
                default: type = SignalServiceGroup.GroupType.UNKNOWN; break;
            }

            if (content.Group.Type != GroupContext.Types.Type.Deliver)
            {
                String name = null;
                IList<String> members = null;
                SignalServiceAttachmentPointer avatar = null;

                if (content.Group.NameOneofCase == GroupContext.NameOneofOneofCase.Name)
                {
                    name = content.Group.Name;
                }

                if (content.Group.Members.Count > 0)
                {
                    members = content.Group.Members;
                }

                if (content.Group.AvatarOneofCase == GroupContext.AvatarOneofOneofCase.Avatar)
                {
                    AttachmentPointer pointer = content.Group.Avatar;

                    avatar = new SignalServiceAttachmentPointer(pointer.Id,
                        pointer.ContentType,
                        pointer.Key.ToByteArray(),
                        envelope.getRelay(),
                        pointer.Digest.ToByteArray(),
                        null,
                        false);
                }

                return new SignalServiceGroup()
                {
                    Type = type,
                    GroupId = content.Group.Id.ToByteArray(),
                    Name = name,
                    Members = members,
                    Avatar = avatar
                };
            }

            return new SignalServiceGroup()
            {
                GroupId = content.Group.Id.ToByteArray(),
                Type = type
            };
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
