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
using libsignalservice.util;
using libsignalservicedotnet.crypto;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;

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
        private readonly CertificateValidator CertificateValidator;

        public SignalServiceCipher(SignalServiceAddress localAddress,
            SignalProtocolStore signalProtocolStore,
            CertificateValidator certificateValidator)
        {
            SignalProtocolStore = signalProtocolStore;
            LocalAddress = localAddress;
            CertificateValidator = certificateValidator;
        }


        public OutgoingPushMessage Encrypt(SignalProtocolAddress destination, UnidentifiedAccess unidentifiedAccess, byte[] unpaddedMessage)
        {
            if (unidentifiedAccess != null)
            {
                SealedSessionCipher sessionCipher = new SealedSessionCipher(SignalProtocolStore, new SignalProtocolAddress(LocalAddress.E164number, 1));
                PushTransportDetails transportDetails = new PushTransportDetails((uint)sessionCipher.GetSessionVersion(destination));
                byte[] ciphertext = sessionCipher.Encrypt(destination, unidentifiedAccess.UnidentifiedCertificate, transportDetails.getPaddedMessageBody(unpaddedMessage));
                String body = Base64.EncodeBytes(ciphertext);
                uint remoteRegistrationId = (uint)sessionCipher.GetRemoteRegistrationId(destination);
                return new OutgoingPushMessage((uint)Envelope.Types.Type.UnidentifiedSender, destination.DeviceId, remoteRegistrationId, body);
            }
            else
            {
                SessionCipher sessionCipher = new SessionCipher(SignalProtocolStore, destination);
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
        /// <param name="callback">Optional callback to call during the decrypt process before it is acked</param>
        /// <returns>a decrypted SignalServiceContent</returns>
        public async Task<SignalServiceContent?> Decrypt(SignalServiceEnvelope envelope, Func<SignalServiceContent?, Task> callback = null)
        {
            Func<Plaintext, Task> callback_func = null;
            if (callback != null)
            {
                callback_func = async (data) => await callback(await DecryptComplete(envelope, data));
            }
            try
            {
                Plaintext plaintext = null;
                if (envelope.HasLegacyMessage())
                {
                    plaintext = await Decrypt(envelope, envelope.GetLegacyMessage(), callback_func);
                }
                else if (envelope.HasContent())
                {
                    plaintext = await Decrypt(envelope, envelope.GetContent(), callback_func);
                }
                if (callback_func != null)
                {
                    return null;
                }
                return await DecryptComplete(envelope, plaintext);
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidMessageException(e);
            }
        }
        private async Task<SignalServiceContent> DecryptComplete(SignalServiceEnvelope envelope, Plaintext plaintext)
        {
            if (envelope.HasLegacyMessage())
            {
                DataMessage message = DataMessage.Parser.ParseFrom(plaintext.Data);
                return new SignalServiceContent(plaintext.Metadata.Sender,
                                    plaintext.Metadata.SenderDevice,
                                    plaintext.Metadata.Timestamp,
                                    plaintext.Metadata.NeedsReceipt)
                {
                    Message = CreateSignalServiceMessage(plaintext.Metadata, message)
                };
            }
            else if (envelope.HasContent())
            {
                Content message = Content.Parser.ParseFrom(plaintext.Data);
                if (message.DataMessageOneofCase == Content.DataMessageOneofOneofCase.DataMessage)
                {
                    return new SignalServiceContent(plaintext.Metadata.Sender,
                                    plaintext.Metadata.SenderDevice,
                                    plaintext.Metadata.Timestamp,
                                    plaintext.Metadata.NeedsReceipt)
                    {
                        Message = CreateSignalServiceMessage(plaintext.Metadata, message.DataMessage)
                    };
                }
                else if (message.SyncMessageOneofCase == Content.SyncMessageOneofOneofCase.SyncMessage)
                {
                    return new SignalServiceContent(plaintext.Metadata.Sender,
                                    plaintext.Metadata.SenderDevice,
                                    plaintext.Metadata.Timestamp,
                                    plaintext.Metadata.NeedsReceipt)
                    {
                        SynchronizeMessage = CreateSynchronizeMessage(plaintext.Metadata, message.SyncMessage)
                    };
                }
                else if (message.CallMessageOneofCase == Content.CallMessageOneofOneofCase.CallMessage)
                {
                    return new SignalServiceContent(plaintext.Metadata.Sender,
                                    plaintext.Metadata.SenderDevice,
                                    plaintext.Metadata.Timestamp,
                                    plaintext.Metadata.NeedsReceipt)
                    {
                        CallMessage = CreateCallMessage(message.CallMessage)
                    };
                }
                else if (message.ReceiptMessageOneofCase == Content.ReceiptMessageOneofOneofCase.ReceiptMessage)
                {
                    return new SignalServiceContent(plaintext.Metadata.Sender,
                                    plaintext.Metadata.SenderDevice,
                                    plaintext.Metadata.Timestamp,
                                    plaintext.Metadata.NeedsReceipt)
                    {
                        ReadMessage = CreateReceiptMessage(plaintext.Metadata, message.ReceiptMessage)
                    };
                }
            }
            return null;
        }
        private class DecryptionCallbackHandler : DecryptionCallback
        {
            public Task handlePlaintext(byte[] data, uint sessionVersion)
            {
                data = GetStrippedMessage(sessionVersion, data);
                return callback(new Plaintext(metadata, data));
            }
            public SessionCipher sessionCipher;
            public Metadata metadata;
            public Func<Plaintext, Task> callback;
        }
        private async Task<Plaintext> Decrypt(SignalServiceEnvelope envelope, byte[] ciphertext, Func<Plaintext, Task> callback = null)
        {
            try
            {
                SignalProtocolAddress sourceAddress = new SignalProtocolAddress(envelope.GetSource(), (uint)envelope.GetSourceDevice());
                SessionCipher sessionCipher = new SessionCipher(SignalProtocolStore, sourceAddress);
                SealedSessionCipher sealedSessionCipher = new SealedSessionCipher(SignalProtocolStore, new SignalProtocolAddress(LocalAddress.E164number, 1));

                byte[] paddedMessage;
                Metadata metadata;
                uint sessionVersion;
                DecryptionCallbackHandler callback_handler = null;
                if (callback != null)
                    callback_handler = new DecryptionCallbackHandler { callback = callback, sessionCipher = sessionCipher };
                if (envelope.IsPreKeySignalMessage())
                {
                    metadata       = new Metadata(envelope.GetSource(), envelope.GetSourceDevice(), envelope.GetTimestamp(), false);
                    if (callback_handler != null)
                    {
                        await sessionCipher.decrypt(new PreKeySignalMessage(ciphertext), callback_handler);
                        return null;
                    }
                    paddedMessage = sessionCipher.decrypt(new PreKeySignalMessage(ciphertext));
                    sessionVersion = sessionCipher.getSessionVersion();
                }
                else if (envelope.IsSignalMessage())
                {
                    if (callback_handler != null)
                    {
                        await sessionCipher.decrypt(new SignalMessage(ciphertext), callback_handler);
                        return null;
                    }
                    paddedMessage = sessionCipher.decrypt(new SignalMessage(ciphertext));
                    metadata       = new Metadata(envelope.GetSource(), envelope.GetSourceDevice(), envelope.GetTimestamp(), false);
                    sessionVersion = sessionCipher.getSessionVersion();
                }
                else if (envelope.IsUnidentifiedSender())
                {
                    var results = sealedSessionCipher.Decrypt(CertificateValidator, ciphertext, (long)envelope.Envelope.ServerTimestamp);
                    paddedMessage = results.Item2;
                    metadata = new Metadata(results.Item1.Name, (int)results.Item1.DeviceId, (long)envelope.Envelope.Timestamp, true);
                    sessionVersion = (uint)sealedSessionCipher.GetSessionVersion(new SignalProtocolAddress(metadata.Sender, (uint)metadata.SenderDevice));
                }
                else
                {
                    throw new InvalidMessageException("Unknown type: " + envelope.GetEnvelopeType() + " from " + envelope.GetSource());
                }
                var data = GetStrippedMessage(sessionVersion, paddedMessage);
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
        private static byte[] GetStrippedMessage(uint sessionVersion, byte[] paddedMessage)
        {
            PushTransportDetails transportDetails = new PushTransportDetails(sessionVersion);
            byte[] data = transportDetails.GetStrippedPaddingMessageBody(paddedMessage);
            return data;
        }


        private SignalServiceDataMessage CreateSignalServiceMessage(Metadata metadata, DataMessage content)
        {
            SignalServiceGroup? groupInfo = CreateGroupInfo(content);
            List<SignalServiceAttachment> attachments = new List<SignalServiceAttachment>();
            bool endSession = ((content.Flags & (uint)DataMessage.Types.Flags.EndSession) != 0);
            bool expirationUpdate = ((content.Flags & (uint)DataMessage.Types.Flags.ExpirationTimerUpdate) != 0);
            bool profileKeyUpdate = ((content.Flags & (uint)DataMessage.Types.Flags.ProfileKeyUpdate) != 0);
            SignalServiceDataMessage.SignalServiceQuote? quote = CreateQuote(content);
            List<SharedContact>? sharedContacts = CreateSharedContacts(content);

            foreach (AttachmentPointer pointer in content.Attachments)
            {
                attachments.Add(CreateAttachmentPointer(pointer));
            }

            if (content.TimestampOneofCase == DataMessage.TimestampOneofOneofCase.Timestamp && (long)content.Timestamp != metadata.Timestamp)
            {
                throw new ProtocolInvalidMessageException(new InvalidMessageException("Timestamps don't match: " + content.Timestamp + " vs " + metadata.Timestamp),
                                                                           metadata.Sender,
                                                                           metadata.SenderDevice);
            }

            return new SignalServiceDataMessage()
            {
                Timestamp = metadata.Timestamp,
                Group = groupInfo,
                Attachments = attachments,
                Body = content.Body,
                EndSession = endSession,
                ExpiresInSeconds = (int)content.ExpireTimer,
                ExpirationUpdate = expirationUpdate,
                ProfileKey = content.ProfileKeyOneofCase == DataMessage.ProfileKeyOneofOneofCase.ProfileKey ? content.ProfileKey.ToByteArray() : null,
                ProfileKeyUpdate = profileKeyUpdate,
                Quote = quote,
                SharedContacts = sharedContacts
            };
        }

        private SignalServiceSyncMessage CreateSynchronizeMessage(Metadata metadata, SyncMessage content)
        {
            if (content.SentOneofCase == SyncMessage.SentOneofOneofCase.Sent)
            {
                SyncMessage.Types.Sent sentContent = content.Sent;
                var unidentifiedStatuses = new Dictionary<string, bool>();

                foreach (var status in sentContent.UnidentifiedStatus)
                {
                    unidentifiedStatuses[status.Destination] = status.Unidentified;
                }

                return SignalServiceSyncMessage.ForSentTranscript(new SentTranscriptMessage(sentContent.Destination,
                                                                           (long)sentContent.Timestamp,
                                                                           CreateSignalServiceMessage(metadata, sentContent.Message),
                                                                           (long)sentContent.ExpirationStartTimestamp,
                                                                           unidentifiedStatuses));
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

            if (content.ContactsOneofCase == SyncMessage.ContactsOneofOneofCase.Contacts)
            {
                AttachmentPointer pointer = content.Contacts.Blob;
                return SignalServiceSyncMessage.ForContacts(new ContactsMessage(CreateAttachmentPointer(pointer), content.Contacts.Complete));
            }

            if (content.GroupsOneofCase == SyncMessage.GroupsOneofOneofCase.Groups)
            {
                AttachmentPointer pointer = content.Groups.Blob;
                return SignalServiceSyncMessage.ForGroups(CreateAttachmentPointer(pointer));
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

            if (content.BlockedOneofCase == SyncMessage.BlockedOneofOneofCase.Blocked)
            {
                List<string> blockedNumbers = new List<string>(content.Blocked.Numbers.Count);
                foreach (var blocked in content.Blocked.Numbers)
                {
                    blockedNumbers.Add(blocked);
                }
                return SignalServiceSyncMessage.ForBlocked(new BlockedListMessage(blockedNumbers, content.Blocked.GroupIds.Select(gid => gid.ToByteArray()).ToList()));
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
                        throw new ProtocolInvalidMessageException(new InvalidMessageException("Unknown state: " + verified.State),
                                                    metadata.Sender, metadata.SenderDevice);
                    }
                    return SignalServiceSyncMessage.ForVerified(new VerifiedMessage(destination, identityKey, verifiedState, Util.CurrentTimeMillis()));
                }
                catch (InvalidKeyException e)
                {
                    throw new ProtocolInvalidKeyException(e, metadata.Sender, metadata.SenderDevice);
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

        private SignalServiceReceiptMessage CreateReceiptMessage(Metadata metadata, ReceiptMessage content)
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
                When = metadata.Timestamp
            };
        }

        private SignalServiceDataMessage.SignalServiceQuote? CreateQuote(DataMessage content)
        {
            if (content.QuoteOneofCase != DataMessage.QuoteOneofOneofCase.Quote)
                return null;

            var attachments = new List<SignalServiceDataMessage.SignalServiceQuotedAttachment>();

            foreach (var pointer in content.Quote.Attachments)
            {
                attachments.Add(new SignalServiceDataMessage.SignalServiceQuotedAttachment(pointer.ContentType,
                    pointer.FileName,
                    pointer.ThumbnailOneofCase == DataMessage.Types.Quote.Types.QuotedAttachment.ThumbnailOneofOneofCase.Thumbnail ? CreateAttachmentPointer(pointer.Thumbnail) : null));
            }

            return new SignalServiceDataMessage.SignalServiceQuote((long)content.Quote.Id,
                new SignalServiceAddress(content.Quote.Author),
                content.Quote.Text,
                attachments);
        }

        private List<SharedContact>? CreateSharedContacts(DataMessage content)
        {
            if (content.Contact.Count <= 0) return null;

            var results = new List<SharedContact>();

            foreach (var contact in content.Contact)
            {
                var name = new Name(contact.Name.DisplayNameOneofCase == DataMessage.Types.Contact.Types.Name.DisplayNameOneofOneofCase.DisplayName ? contact.Name.DisplayName : null,
                    contact.Name.GivenNameOneofCase == DataMessage.Types.Contact.Types.Name.GivenNameOneofOneofCase.GivenName ? contact.Name.GivenName : null,
                    contact.Name.FamilyNameOneofCase == DataMessage.Types.Contact.Types.Name.FamilyNameOneofOneofCase.FamilyName ? contact.Name.FamilyName : null,
                    contact.Name.PrefixOneofCase == DataMessage.Types.Contact.Types.Name.PrefixOneofOneofCase.Prefix ? contact.Name.Prefix : null,
                    contact.Name.SuffixOneofCase == DataMessage.Types.Contact.Types.Name.SuffixOneofOneofCase.Suffix ? contact.Name.DisplayName : null,
                    contact.Name.MiddleNameOneofCase == DataMessage.Types.Contact.Types.Name.MiddleNameOneofOneofCase.MiddleName ? contact.Name.MiddleName : null);

                Avatar? avatar = null;
                string? organization = null;
                if (contact.Address.Count > 0)
                {
                    foreach (var address in contact.Address)
                    {
                        //TODO
                        /*
                        SharedContact.PostalAddress.Type type = SharedContact.PostalAddress.Type.HOME;

                        switch (address.getType())
                        {
                            case WORK: type = SharedContact.PostalAddress.Type.WORK; break;
                            case HOME: type = SharedContact.PostalAddress.Type.HOME; break;
                            case CUSTOM: type = SharedContact.PostalAddress.Type.CUSTOM; break;
                        }

                        builder.withAddress(SharedContact.PostalAddress.newBuilder()
                                                                       .setCity(address.getCity())
                                                                       .setCountry(address.getCountry())
                                                                       .setLabel(address.getLabel())
                                                                       .setNeighborhood(address.getNeighborhood())
                                                                       .setPobox(address.getPobox())
                                                                       .setPostcode(address.getPostcode())
                                                                       .setRegion(address.getRegion())
                                                                       .setStreet(address.getStreet())
                                                                       .setType(type)
                                                                       .build());
                                                                       */
                    }
                }

                if (contact.Number.Count > 0)
                {
                    foreach (var phone in contact.Number)
                    {
                        //TODO
                        /*
                        SharedContact.Phone.Type type = SharedContact.Phone.Type.HOME;

                        switch (phone.getType())
                        {
                            case HOME: type = SharedContact.Phone.Type.HOME; break;
                            case WORK: type = SharedContact.Phone.Type.WORK; break;
                            case MOBILE: type = SharedContact.Phone.Type.MOBILE; break;
                            case CUSTOM: type = SharedContact.Phone.Type.CUSTOM; break;
                        }

                        builder.withPhone(SharedContact.Phone.newBuilder()
                                                             .setLabel(phone.getLabel())
                                                             .setType(type)
                                                             .setValue(phone.getValue())
                                                             .build());
                                                             */
                    }
                }

                if (contact.Email.Count > 0)
                {
                    foreach (var email in contact.Email)
                    {
                        //TODO
                        /*
                        SharedContact.Email.Type type = SharedContact.Email.Type.HOME;

                        switch (email.getType())
                        {
                            case HOME: type = SharedContact.Email.Type.HOME; break;
                            case WORK: type = SharedContact.Email.Type.WORK; break;
                            case MOBILE: type = SharedContact.Email.Type.MOBILE; break;
                            case CUSTOM: type = SharedContact.Email.Type.CUSTOM; break;
                        }

                        builder.withEmail(SharedContact.Email.newBuilder()
                                                             .setLabel(email.getLabel())
                                                             .setType(type)
                                                             .setValue(email.getValue())
                                                             .build());
                                                             */
                    }
                }

                if (contact.AvatarOneofCase == DataMessage.Types.Contact.AvatarOneofOneofCase.Avatar)
                {
                    avatar = new Avatar(CreateAttachmentPointer(contact.Avatar.Avatar_), contact.Avatar.IsProfile);
                }

                if (contact.OrganizationOneofCase == DataMessage.Types.Contact.OrganizationOneofOneofCase.Organization)
                {
                    organization = contact.Organization;
                }

                results.Add(new SharedContact(name, avatar, null, null, null, organization)); //TODO
            }
            return results;
        }

        private SignalServiceAttachmentPointer CreateAttachmentPointer(AttachmentPointer pointer)
        {
            uint? size = null;
            if (pointer.SizeOneofCase == AttachmentPointer.SizeOneofOneofCase.Size)
            {
                size = pointer.Size;
            }
            return new SignalServiceAttachmentPointer(pointer.Id,
                pointer.ContentType,
                pointer.Key.ToByteArray(),
                size,
                pointer.ThumbnailOneofCase == AttachmentPointer.ThumbnailOneofOneofCase.Thumbnail ? pointer.Thumbnail.ToByteArray() : null,
                (int)pointer.Width,
                (int)pointer.Height,
                pointer.DigestOneofCase == AttachmentPointer.DigestOneofOneofCase.Digest ? pointer.Digest.ToByteArray() : null,
                pointer.FileNameOneofCase == AttachmentPointer.FileNameOneofOneofCase.FileName ? pointer.FileName : null,
                (pointer.Flags & (uint)AttachmentPointer.Types.Flags.VoiceMessage) != 0);
        }

        private SignalServiceGroup? CreateGroupInfo(DataMessage content)
        {
            if (content.GroupOneofCase == DataMessage.GroupOneofOneofCase.None) return null;

            var type = content.Group.Type switch
            {
                GroupContext.Types.Type.Deliver => SignalServiceGroup.GroupType.DELIVER,
                GroupContext.Types.Type.Update => SignalServiceGroup.GroupType.UPDATE,
                GroupContext.Types.Type.Quit => SignalServiceGroup.GroupType.QUIT,
                GroupContext.Types.Type.RequestInfo => SignalServiceGroup.GroupType.REQUEST_INFO,
                _ => SignalServiceGroup.GroupType.UNKNOWN,
            };
            if (content.Group.Type != GroupContext.Types.Type.Deliver)
            {
                string? name = null;
                IList<string>? members = null;
                SignalServiceAttachmentPointer? avatar = null;

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
                        pointer.SizeOneofCase == AttachmentPointer.SizeOneofOneofCase.Size ? pointer.Size : 0,
                        null,
                        0, 0,
                        pointer.DigestOneofCase == AttachmentPointer.DigestOneofOneofCase.Digest ? pointer.Digest.ToByteArray() : null,
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

    internal class Metadata
    {
        public readonly string Sender;
        public readonly int SenderDevice;
        public readonly long Timestamp;
        public readonly bool NeedsReceipt;

        public Metadata(string sender, int senderDevice, long timestamp, bool needsReceipt)
        {
            Sender       = sender;
            SenderDevice = senderDevice;
            Timestamp    = timestamp;
            NeedsReceipt = needsReceipt;
        }
    }

    internal class Plaintext
    {
        public readonly Metadata Metadata;
        public readonly byte[] Data;

        public Plaintext(Metadata metadata, byte[] data)
        {
            this.Metadata = metadata;
            this.Data     = data;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
