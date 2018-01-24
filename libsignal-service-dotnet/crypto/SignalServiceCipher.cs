using Google.Protobuf;
using libsignal;
using libsignal.protocol;
using libsignal.state;
using libsignal_service_dotnet.messages.calls;
using libsignalservice.messages;
using libsignalservice.messages.multidevice;
using libsignalservice.push;
using libsignalservice.util;

/**
 * Copyright (C) 2015-2017 smndtrl, golf1052
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;

namespace libsignalservice.crypto
{
    /// <summary>
    /// This is used to decrypt received <see cref="SignalServiceEnvelope"/>s
    /// </summary>
    public class SignalServiceCipher
    {
        private static readonly string TAG = "SignalServiceCipher";

        private readonly SignalProtocolStore signalProtocolStore;
        private readonly SignalServiceAddress localAddress;

        public SignalServiceCipher(SignalServiceAddress localAddress, SignalProtocolStore signalProtocolStore)
        {
            this.signalProtocolStore = signalProtocolStore;
            this.localAddress = localAddress;
        }

        public OutgoingPushMessage encrypt(SignalProtocolAddress destination, byte[] unpaddedMessage, bool legacy, bool silent)
        {
            SessionCipher sessionCipher = new SessionCipher(signalProtocolStore, destination);
            PushTransportDetails transportDetails = new PushTransportDetails(sessionCipher.getSessionVersion());
            CiphertextMessage message = sessionCipher.encrypt(transportDetails.getPaddedMessageBody(unpaddedMessage));
            uint remoteRegistrationId = sessionCipher.getRemoteRegistrationId();
            String body = Base64.encodeBytes(message.serialize());

            uint type;

            switch (message.getType())
            {
                case CiphertextMessage.PREKEY_TYPE: type = (uint)Envelope.Types.Type.PrekeyBundle; break; // todo check
                case CiphertextMessage.WHISPER_TYPE: type = (uint)Envelope.Types.Type.Ciphertext; break; // todo check
                default: throw new Exception("Bad type: " + message.getType());
            }

            return new OutgoingPushMessage(type,
                destination.DeviceId,
                remoteRegistrationId,
                legacy ? body : null,
                legacy ? null : body,
                silent);
        }

        /// <summary>
        /// Decrypt a received <see cref="SignalServiceEnvelope"/>
        /// </summary>
        /// <param name="envelope">The received SignalServiceEnvelope</param>
        /// <returns>a decrypted SignalServiceContent</returns>
        public SignalServiceContent decrypt(SignalServiceEnvelope envelope)
        {
            try
            {
                SignalServiceContent content = new SignalServiceContent();

                if (envelope.hasLegacyMessage())
                {
                    DataMessage message = DataMessage.Parser.ParseFrom(decrypt(envelope, envelope.getLegacyMessage()));
                    content = new SignalServiceContent()
                    {
                        Message = createSignalServiceMessage(envelope, message)
                    };
                }
                else if (envelope.hasContent())
                {
                    Content message = Content.Parser.ParseFrom(decrypt(envelope, envelope.getContent()));

                    if (message.DataMessageOneofCase == Content.DataMessageOneofOneofCase.DataMessage)
                    {
                        content = new SignalServiceContent()
                        {
                            Message = createSignalServiceMessage(envelope, message.DataMessage)
                        };
                    }
                    else if (message.SyncMessageOneofCase == Content.SyncMessageOneofOneofCase.SyncMessage && localAddress.getNumber().Equals(envelope.getSource()))
                    {
                        content = new SignalServiceContent()
                        {
                            SynchronizeMessage = createSynchronizeMessage(envelope, message.SyncMessage)
                        };
                    }
                    else if (message.CallMessageOneofCase == Content.CallMessageOneofOneofCase.CallMessage)
                    {
                        content = new SignalServiceContent()
                        {
                            CallMessage = createCallMessage(message.CallMessage)
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

        private byte[] decrypt(SignalServiceEnvelope envelope, byte[] ciphertext)

        {
            SignalProtocolAddress sourceAddress = new SignalProtocolAddress(envelope.getSource(), (uint)envelope.getSourceDevice());
            SessionCipher sessionCipher = new SessionCipher(signalProtocolStore, sourceAddress);

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

        private SignalServiceDataMessage createSignalServiceMessage(SignalServiceEnvelope envelope, DataMessage content)
        {
            SignalServiceGroup groupInfo = createGroupInfo(envelope, content);
            List<SignalServiceAttachment> attachments = new List<SignalServiceAttachment>();
            bool endSession = ((content.Flags & (uint)DataMessage.Types.Flags.EndSession) != 0);
            bool expirationUpdate = ((content.Flags & (uint)DataMessage.Types.Flags.ExpirationTimerUpdate) != 0);

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
                ExpirationUpdate = expirationUpdate
            };
        }

        private SignalServiceSyncMessage createSynchronizeMessage(SignalServiceEnvelope envelope, SyncMessage content)
        {
            if (content.SentOneofCase == SyncMessage.SentOneofOneofCase.Sent)
            {
                SyncMessage.Types.Sent sentContent = content.Sent;
                return SignalServiceSyncMessage.forSentTranscript(new SentTranscriptMessage(sentContent.Destination,
                                                                           (long)sentContent.Timestamp,
                                                                           createSignalServiceMessage(envelope, sentContent.Message),
                                                                           (long)sentContent.ExpirationStartTimestamp));
            }

            if (content.RequestOneofCase == SyncMessage.RequestOneofOneofCase.Request)
            {
                return SignalServiceSyncMessage.forRequest(new RequestMessage(content.Request));
            }

            if (content.Read.Count > 0)
            {
                List<ReadMessage> readMessages = new List<ReadMessage>();

                foreach (SyncMessage.Types.Read read in content.Read)
                {
                    readMessages.Add(new ReadMessage(read.Sender, (long)read.Timestamp));
                }

                return SignalServiceSyncMessage.forRead(readMessages);
            }

            if (content.Verified.Count > 0)
            {
                try
                {
                    List<VerifiedMessage> verifiedMessages = new List<VerifiedMessage>();

                    foreach (SyncMessage.Types.Verified verified in content.Verified)
                    {
                        string destination = verified.Destination;
                        IdentityKey identityKey = new IdentityKey(verified.IdentityKey.ToByteArray(), 0);

                        VerifiedMessage.VerifiedState verifiedState;

                        if (verified.State == SyncMessage.Types.Verified.Types.State.Default)
                        {
                            verifiedState = VerifiedMessage.VerifiedState.Default;
                        }
                        else if (verified.State == SyncMessage.Types.Verified.Types.State.Verified)
                        {
                            verifiedState = VerifiedMessage.VerifiedState.Verified;
                        }
                        else if (verified.State == SyncMessage.Types.Verified.Types.State.Unverified)
                        {
                            verifiedState = VerifiedMessage.VerifiedState.Unverified;
                        }
                        else
                        {
                            throw new InvalidMessageException("Unknown state: " + verified.State);
                        }

                        verifiedMessages.Add(new VerifiedMessage(destination, identityKey, verifiedState));
                    }
                }
                catch (InvalidKeyException e)
                {
                    throw new InvalidMessageException(e);
                }
            }

            return SignalServiceSyncMessage.empty();
        }

        private SignalServiceCallMessage createCallMessage(CallMessage content)
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

        private SignalServiceGroup createGroupInfo(SignalServiceEnvelope envelope, DataMessage content)
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
}
