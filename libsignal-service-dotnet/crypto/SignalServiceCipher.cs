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
using libsignalservice.util;
using libsignalservicedotnet.crypto;

namespace libsignalservice.crypto
{
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
                string body = Base64.EncodeBytes(ciphertext);
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
        /// <returns>a decrypted SignalServiceContent</returns>
        public SignalServiceContent? Decrypt(SignalServiceEnvelope envelope)
        {
            try
            {
                if (envelope.HasLegacyMessage())
                {
                    Plaintext plaintext = Decrypt(envelope, envelope.GetLegacyMessage());
                    DataMessage message = DataMessage.Parser.ParseFrom(plaintext.Data);
                    return new SignalServiceContent(CreateSignalServiceMessage(plaintext.Metadata, message),
                        plaintext.Metadata.Sender,
                        plaintext.Metadata.SenderDevice,
                        plaintext.Metadata.Timestamp,
                        plaintext.Metadata.NeedsReceipt);
                }
                else if (envelope.HasContent())
                {
                    Plaintext plaintext = Decrypt(envelope, envelope.Envelope.Content.ToByteArray());
                    Content message = Content.Parser.ParseFrom(plaintext.Data);
                    if (message.DataMessage != null)
                    {
                        return new SignalServiceContent(CreateSignalServiceMessage(plaintext.Metadata, message.DataMessage),
                            plaintext.Metadata.Sender,
                            plaintext.Metadata.SenderDevice,
                            plaintext.Metadata.Timestamp,
                            plaintext.Metadata.NeedsReceipt);
                    }
                    else if (message.SyncMessage != null)
                    {
                        return new SignalServiceContent(CreateSynchronizeMessage(plaintext.Metadata, message.SyncMessage),
                            plaintext.Metadata.Sender,
                            plaintext.Metadata.SenderDevice,
                            plaintext.Metadata.Timestamp,
                            plaintext.Metadata.NeedsReceipt);
                    }
                    else if (message.CallMessage != null)
                    {
                        return new SignalServiceContent(CreateCallMessage(message.CallMessage),
                            plaintext.Metadata.Sender,
                            plaintext.Metadata.SenderDevice,
                            plaintext.Metadata.Timestamp,
                            plaintext.Metadata.NeedsReceipt);
                    }
                    else if (message.ReceiptMessage != null)
                    {
                        return new SignalServiceContent(CreateReceiptMessage(plaintext.Metadata, message.ReceiptMessage),
                            plaintext.Metadata.Sender,
                            plaintext.Metadata.SenderDevice,
                            plaintext.Metadata.Timestamp,
                            plaintext.Metadata.NeedsReceipt);
                    }
                    else if (message.TypingMessage != null)
                    {
                        return new SignalServiceContent(CreateTypingMessage(plaintext.Metadata, message.TypingMessage),
                            plaintext.Metadata.Sender,
                            plaintext.Metadata.SenderDevice,
                            plaintext.Metadata.Timestamp,
                            false);
                    }
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
                SessionCipher sessionCipher = new SessionCipher(SignalProtocolStore, sourceAddress);
                SealedSessionCipher sealedSessionCipher = new SealedSessionCipher(SignalProtocolStore, new SignalProtocolAddress(LocalAddress.E164number, 1));

                byte[] paddedMessage;
                Metadata metadata;
                uint sessionVersion;

                if (envelope.IsPreKeySignalMessage())
                {
                    paddedMessage = sessionCipher.decrypt(new PreKeySignalMessage(ciphertext));
                    metadata       = new Metadata(envelope.GetSource(), envelope.GetSourceDevice(), envelope.GetTimestamp(), false);
                    sessionVersion = sessionCipher.getSessionVersion();
                }
                else if (envelope.IsSignalMessage())
                {
                    paddedMessage = sessionCipher.decrypt(new SignalMessage(ciphertext));
                    metadata       = new Metadata(envelope.GetSource(), envelope.GetSourceDevice(), envelope.GetTimestamp(), false);
                    sessionVersion = sessionCipher.getSessionVersion();
                }
                else if (envelope.IsUnidentifiedSender())
                {
                    var results = sealedSessionCipher.Decrypt(CertificateValidator, ciphertext, (long)envelope.Envelope.ServerTimestamp);
                    paddedMessage = results.Item2;
                    metadata = new Metadata(results.Item1.Name, (int) results.Item1.DeviceId, (long) envelope.Envelope.Timestamp, true);
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

        private SignalServiceDataMessage CreateSignalServiceMessage(Metadata metadata, DataMessage content)
        {
            SignalServiceGroup? groupInfo = CreateGroupInfo(content);
            List<SignalServiceAttachment> attachments = new List<SignalServiceAttachment>();
            bool endSession = ((content.Flags & (uint)DataMessage.Types.Flags.EndSession) != 0);
            bool expirationUpdate = ((content.Flags & (uint)DataMessage.Types.Flags.ExpirationTimerUpdate) != 0);
            bool profileKeyUpdate = ((content.Flags & (uint)DataMessage.Types.Flags.ProfileKeyUpdate) != 0);
            SignalServiceDataMessage.SignalServiceQuote? quote = CreateQuote(content);
            List<SharedContact>? sharedContacts = CreateSharedContacts(content);
            SignalServiceDataMessage.SignalServicePreview? preview = CreatePreview(content);

            foreach (AttachmentPointer pointer in content.Attachments)
            {
                attachments.Add(CreateAttachmentPointer(pointer));
            }

            if (content.HasTimestamp && (long)content.Timestamp != metadata.Timestamp)
            {
                throw new ProtocolInvalidMessageException(new InvalidMessageException("Timestamps don't match: " + content.Timestamp + " vs " + metadata.Timestamp),
                                                                           metadata.Sender,
                                                                           metadata.SenderDevice);
            }

            return new SignalServiceDataMessage(metadata.Timestamp,
                groupInfo,
                attachments,
                content.Body,
                endSession,
                (int)content.ExpireTimer,
                expirationUpdate,
                content.HasProfileKey ? content.ProfileKey.ToByteArray() : null,
                profileKeyUpdate,
                quote,
                sharedContacts,
                preview);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="metadata"></param>
        /// <param name="content"></param>
        /// <returns></returns>
        /// <exception cref="ProtocolInvalidMessageException"></exception>
        /// <exception cref="ProtocolInvalidKeyException"></exception>
        private SignalServiceSyncMessage CreateSynchronizeMessage(Metadata metadata, SyncMessage content)
        {
            if (content.Sent != null)
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

            if (content.Request != null)
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

            if (content.Contacts != null)
            {
                AttachmentPointer pointer = content.Contacts.Blob;
                return SignalServiceSyncMessage.ForContacts(new ContactsMessage(CreateAttachmentPointer(pointer), content.Contacts.Complete));
            }

            if (content.Groups != null)
            {
                AttachmentPointer pointer = content.Groups.Blob;
                return SignalServiceSyncMessage.ForGroups(CreateAttachmentPointer(pointer));
            }

            if (content.Verified != null)
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

            if (content.Blocked != null)
            {
                List<string> blockedNumbers = new List<string>(content.Blocked.Numbers.Count);
                foreach (var blocked in content.Blocked.Numbers)
                {
                    blockedNumbers.Add(blocked);
                }
                return SignalServiceSyncMessage.ForBlocked(new BlockedListMessage(blockedNumbers, content.Blocked.GroupIds.Select(gid => gid.ToByteArray()).ToList()));
            }

            return SignalServiceSyncMessage.Empty();
        }

        private SignalServiceCallMessage CreateCallMessage(CallMessage content)
        {
            if (content.Offer != null)
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
            else if (content.Answer != null)
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
            else if (content.Hangup != null)
            {
                return new SignalServiceCallMessage()
                {
                    HangupMessage = new HangupMessage()
                    {
                        Id = content.Hangup.Id,
                    }
                };
            }
            else if (content.Busy != null)
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

            return new SignalServiceReceiptMessage()
            {
                ReceiptType = type,
                Timestamps = content.Timestamp.ToList(),
                When = metadata.Timestamp
            };
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="metadata"></param>
        /// <param name="content"></param>
        /// <returns></returns>
        /// <exception cref="ProtocolInvalidMessageException"></exception>
        private SignalServiceTypingMessage CreateTypingMessage(Metadata metadata, TypingMessage content)
        {
            SignalServiceTypingMessage.Action action;

            if (content.Action == TypingMessage.Types.Action.Started) action = SignalServiceTypingMessage.Action.STARTED;
            else if (content.Action == TypingMessage.Types.Action.Stopped) action = SignalServiceTypingMessage.Action.STOPPED;
            else action = SignalServiceTypingMessage.Action.UNKNOWN;

            if (content.HasTimestamp && (long)content.Timestamp != metadata.Timestamp)
            {
                throw new ProtocolInvalidMessageException(new InvalidMessageException($"Timestamps don't match: {content.Timestamp} vs {metadata.Timestamp}"),
                    metadata.Sender,
                    metadata.SenderDevice);
            }

            return new SignalServiceTypingMessage(action, (long)content.Timestamp,
                content.HasGroupId ? content.GroupId.ToByteArray() : null);
        }

        private SignalServiceDataMessage.SignalServiceQuote? CreateQuote(DataMessage content)
        {
            if (content.Quote == null)
                return null;

            var attachments = new List<SignalServiceDataMessage.SignalServiceQuotedAttachment>();

            foreach (var attachment in content.Quote.Attachments)
            {
                attachments.Add(new SignalServiceDataMessage.SignalServiceQuotedAttachment(attachment.ContentType,
                    attachment.FileName,
                    attachment.Thumbnail != null ? CreateAttachmentPointer(attachment.Thumbnail) : null));
            }

            return new SignalServiceDataMessage.SignalServiceQuote((long)content.Quote.Id,
                new SignalServiceAddress(content.Quote.Author),
                content.Quote.Text,
                attachments);
        }

        private SignalServiceDataMessage.SignalServicePreview? CreatePreview(DataMessage content)
        {
            if (content.Preview == null) return null;

            SignalServiceAttachment? attachment = null;

            if (content.Preview.Image != null)
            {
                attachment = CreateAttachmentPointer(content.Preview.Image);
            }

            return new SignalServiceDataMessage.SignalServicePreview(content.Preview.Url,
                content.Preview.Title,
                attachment);
        }

        private List<SharedContact>? CreateSharedContacts(DataMessage content)
        {
            if (content.Contact.Count <= 0) return null;

            var results = new List<SharedContact>();

            foreach (var contact in content.Contact)
            {
                Name name = new Name(contact.Name.DisplayName,
                    contact.Name.GivenName,
                    contact.Name.FamilyName,
                    contact.Name.Prefix,
                    contact.Name.Suffix,
                    contact.Name.MiddleName);

                List<PostalAddress> postalAddresses = new List<PostalAddress>();
                if (contact.Address.Count > 0)
                {
                    foreach (var address in contact.Address)
                    {
                        PostalAddress.PostalAddressType postalAddressType = PostalAddress.PostalAddressType.HOME;

                        switch (address.Type)
                        {
                            case DataMessage.Types.Contact.Types.PostalAddress.Types.Type.Work: postalAddressType = PostalAddress.PostalAddressType.WORK; break;
                            case DataMessage.Types.Contact.Types.PostalAddress.Types.Type.Home: postalAddressType = PostalAddress.PostalAddressType.HOME; break;
                            case DataMessage.Types.Contact.Types.PostalAddress.Types.Type.Custom: postalAddressType = PostalAddress.PostalAddressType.CUSTOM; break;
                        }

                        postalAddresses.Add(new PostalAddress(postalAddressType,
                            address.Label,
                            address.Street,
                            address.Pobox,
                            address.Neighborhood,
                            address.City,
                            address.Region,
                            address.Postcode,
                            address.Country));
                    }
                }

                List<Phone> phones = new List<Phone>();
                if (contact.Number.Count > 0)
                {
                    foreach (var phone in contact.Number)
                    {
                        Phone.PhoneType phoneType = Phone.PhoneType.HOME;

                        switch (phone.Type)
                        {
                            case DataMessage.Types.Contact.Types.Phone.Types.Type.Home: phoneType = Phone.PhoneType.HOME; break;
                            case DataMessage.Types.Contact.Types.Phone.Types.Type.Work: phoneType = Phone.PhoneType.WORK; break;
                            case DataMessage.Types.Contact.Types.Phone.Types.Type.Mobile: phoneType = Phone.PhoneType.MOBILE; break;
                            case DataMessage.Types.Contact.Types.Phone.Types.Type.Custom: phoneType = Phone.PhoneType.CUSTOM; break;
                        }

                        phones.Add(new Phone(phone.Value, phoneType, phone.Label));
                    }
                }

                List<Email> emails = new List<Email>();
                if (contact.Email.Count > 0)
                {
                    foreach (var email in contact.Email)
                    {
                        Email.EmailType emailType = Email.EmailType.HOME;

                        switch (email.Type)
                        {
                            case DataMessage.Types.Contact.Types.Email.Types.Type.Home: emailType = Email.EmailType.HOME; break;
                            case DataMessage.Types.Contact.Types.Email.Types.Type.Work: emailType = Email.EmailType.WORK; break;
                            case DataMessage.Types.Contact.Types.Email.Types.Type.Mobile: emailType = Email.EmailType.MOBILE; break;
                            case DataMessage.Types.Contact.Types.Email.Types.Type.Custom: emailType = Email.EmailType.CUSTOM; break;
                        }

                        emails.Add(new Email(email.Value, emailType, email.Label));
                    }
                }

                Avatar? avatar = null;
                if (contact.Avatar != null)
                {
                    avatar = new Avatar(CreateAttachmentPointer(contact.Avatar.Avatar_), contact.Avatar.IsProfile);
                }

                string? organization = null;
                if (contact.HasOrganization)
                {
                    organization = contact.Organization;
                }

                SharedContact sharedContact = new SharedContact(name, avatar,
                    phones.Count > 0 ? phones : null,
                    emails.Count > 0 ? emails : null,
                    postalAddresses.Count > 0 ? postalAddresses : null,
                    organization);
                results.Add(sharedContact);
            }

            return results;
        }

        private SignalServiceAttachmentPointer CreateAttachmentPointer(AttachmentPointer pointer)
        {
            return new SignalServiceAttachmentPointer(pointer.Id,
                pointer.ContentType,
                pointer.Key.ToByteArray(),
                pointer.HasSize ? pointer.Size : (uint?)null,
                pointer.HasThumbnail ? pointer.Thumbnail.ToByteArray() : null,
                (int)pointer.Width,
                (int)pointer.Height,
                pointer.HasDigest ? pointer.Digest.ToByteArray() : null,
                pointer.HasFileName ? pointer.FileName : null,
                (pointer.Flags & (uint)AttachmentPointer.Types.Flags.VoiceMessage) != 0,
                pointer.HasCaption ? pointer.Caption : null);
        }

        private SignalServiceGroup? CreateGroupInfo(DataMessage content)
        {
            if (content.Group == null) return null;

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

                if (content.Group.HasName)
                {
                    name = content.Group.Name;
                }

                if (content.Group.Members.Count > 0)
                {
                    members = content.Group.Members;
                }

                if (content.Group.Avatar != null)
                {
                    AttachmentPointer pointer = content.Group.Avatar;

                    avatar = new SignalServiceAttachmentPointer(pointer.Id,
                        pointer.ContentType,
                        pointer.Key.ToByteArray(),
                        pointer.HasSize ? pointer.Size : 0,
                        null,
                        0, 0,
                        pointer.HasDigest ? pointer.Digest.ToByteArray() : null,
                        null,
                        false,
                        null);
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
}
