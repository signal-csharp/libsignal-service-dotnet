using Google.Protobuf;
using libsignal;
using libsignal.state;
using libsignal_service_dotnet.messages.calls;
using libsignalservice.crypto;
using libsignalservice.messages;
using libsignalservice.messages.multidevice;
using libsignalservice.push;
using libsignalservice.push.exceptions;
using libsignalservice.util;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

namespace libsignalservice
{
    /// <summary>
    /// The main interface for sending Signal Service messages.
    /// </summary>
    public class SignalServiceMessageSender
    {
        private static string TAG = "SignalServiceMessageSender";

        private readonly PushServiceSocket socket;
        private readonly SignalProtocolStore store;
        private readonly SignalServiceAddress localAddress;
        private readonly SignalServiceMessagePipe pipe;
        private readonly EventListener eventListener;
        private readonly CancellationToken Token;
        private readonly StaticCredentialsProvider CredentialsProvider;

        /// <summary>
        /// Construct a SignalServiceMessageSender
        /// </summary>
        /// <param name="urls">The URL of the Signal Service.</param>
        /// <param name="user">The Signal Service username (eg phone number).</param>
        /// <param name="password">The Signal Service user password</param>
        /// <param name="store">The SignalProtocolStore.</param>
        /// <param name="eventListener">An optional event listener, which fires whenever sessions are
        /// setup or torn down for a recipient.</param>
        /// <param name="userAgent"></param>
        public SignalServiceMessageSender(CancellationToken token, SignalServiceUrl[] urls,
                                       string user, string password, int deviceId,
                                       SignalProtocolStore store,
                                       SignalServiceMessagePipe pipe,
                                       EventListener eventListener, string userAgent)
        {
            Token = token;
            CredentialsProvider = new StaticCredentialsProvider(user, password, null, deviceId);
            this.socket = new PushServiceSocket(urls, CredentialsProvider, userAgent);
            this.store = store;
            this.localAddress = new SignalServiceAddress(user);
            this.pipe = pipe;
            this.eventListener = eventListener;
        }

        /// <summary>
        /// Send a delivery receipt for a received message.  It is not necessary to call this
        /// when receiving messages through <see cref="SignalServiceMessagePipe"/>
        /// </summary>
        /// <param name="recipient">The sender of the received message you're acknowledging.</param>
        /// <param name="messageId">The message id of the received message you're acknowledging.</param>
        public void sendDeliveryReceipt(SignalServiceAddress recipient, ulong messageId)
        {
            this.socket.sendReceipt(recipient.getNumber(), messageId, recipient.getRelay());
        }

        public void sendCallMessage(SignalServiceAddress recipient, SignalServiceCallMessage message)
        {
            byte[] content = createCallContent(message);
            sendMessage(recipient, Util.CurrentTimeMillis(), content, true);
        }

        /// <summary>
        /// Send a message to a single recipient.
        /// </summary>
        /// <param name="recipient">The message's destination.</param>
        /// <param name="message">The message.</param>
        public void sendMessage(SignalServiceAddress recipient, SignalServiceDataMessage message)
        {
            byte[] content = createMessageContent(message);
            long timestamp = message.Timestamp;
            bool silent = message.Group != null && message.Group.Type == SignalServiceGroup.GroupType.REQUEST_INFO;
            var resp = sendMessage(recipient, timestamp, content, silent);

            if (resp.needsSync)
            {
                byte[] syncMessage = createMultiDeviceSentTranscriptContent(content, new May<SignalServiceAddress>(recipient), (ulong)timestamp);
                sendMessage(localAddress, timestamp, syncMessage, false);
            }

            if (message.EndSession)
            {
                store.DeleteAllSessions(recipient.getNumber());

                if (eventListener != null)
                {
                    eventListener.onSecurityEvent(recipient);
                }
            }
        }

        /// <summary>
        /// Send a message to a group.
        /// </summary>
        /// <param name="recipients">The group members.</param>
        /// <param name="message">The group message.</param>
        public void sendMessage(List<SignalServiceAddress> recipients, SignalServiceDataMessage message)
        {
            byte[] content = createMessageContent(message);
            long timestamp = message.Timestamp;
            SendMessageResponseList response = sendMessage(recipients, timestamp, content);
            try
            {
                if (response != null && response.NeedsSync)
                {
                    byte[] syncMessage = createMultiDeviceSentTranscriptContent(content, May<SignalServiceAddress>.NoValue, (ulong)timestamp);
                    sendMessage(localAddress, timestamp, syncMessage, false);
                }
            }
            catch (UntrustedIdentityException e)
            {
                response.UntrustedIdentities.Add(e);
            }

            if (response.HasExceptions())
            {
                throw new EncapsulatedExceptions(response.UntrustedIdentities, response.UnregisteredUsers, response.NetworkExceptions);
            }
        }

        public void sendMessage(SignalServiceSyncMessage message)
        {
            byte[] content;

            if (message.getContacts().HasValue)
            {
                content = createMultiDeviceContactsContent(message.getContacts().ForceGetValue().Contacts.asStream(),
                    message.getContacts().ForceGetValue().Complete);
            }
            else if (message.getGroups().HasValue)
            {
                content = createMultiDeviceGroupsContent(message.getGroups().ForceGetValue().asStream());
            }
            else if (message.getRead().HasValue)
            {
                content = createMultiDeviceReadContent(message.getRead().ForceGetValue());
            }
            else if (message.getBlockedList().HasValue)
            {
                content = createMultiDeviceBlockedContent(message.getBlockedList().ForceGetValue());
            }
            else if (message.getVerified().HasValue)
            {
                content = createMultiDeviceVerifiedContent(message.getVerified().ForceGetValue());
            }
            else
            {
                throw new Exception("Unsupported sync message!");
            }

            sendMessage(localAddress, Util.CurrentTimeMillis(), content, false);
        }

        public void setSoTimeoutMillis(long soTimeoutMillis)
        {
            socket.setSoTimeoutMillis(soTimeoutMillis);
        }

        public void cancelInFlightRequests()
        {
            socket.cancelInFlightRequests();
        }

        private byte[] createMessageContent(SignalServiceDataMessage message)// throws IOException
        {
            Content content = new Content();
            DataMessage dataMessage = new DataMessage { };
            IList<AttachmentPointer> pointers = createAttachmentPointers(message.Attachments);

            if (pointers.Count != 0)
            {
                dataMessage.Attachments.AddRange(pointers);
            }

            if (message.Body != null)
            {
                dataMessage.Body = message.Body;
            }

            if (message.Group != null)
            {
                dataMessage.Group = createGroupContent(message.Group);
            }

            if (message.EndSession)
            {
                dataMessage.Flags = (uint)DataMessage.Types.Flags.EndSession;
            }

            if (message.ExpirationUpdate)
            {
                dataMessage.Flags = (uint)DataMessage.Types.Flags.ExpirationTimerUpdate;
            }

            if (message.ExpiresInSeconds > 0)
            {
                dataMessage.ExpireTimer = (uint)message.ExpiresInSeconds;
            }

            content.DataMessage = dataMessage;
            return content.ToByteArray();
        }

        private byte[] createCallContent(SignalServiceCallMessage callMessage)
        {
            Content content = new Content();
            CallMessage pushCallMessage = new CallMessage();

            if (callMessage.OfferMessage != null)
            {
                pushCallMessage.Offer = new CallMessage.Types.Offer()
                {
                    Id = callMessage.OfferMessage.Id,
                    Description = callMessage.OfferMessage.Description
                };
            }
            else if (callMessage.AnswerMessage != null)
            {
                pushCallMessage.Answer = new CallMessage.Types.Answer()
                {
                    Id = callMessage.AnswerMessage.Id,
                    Description = callMessage.AnswerMessage.Description
                };
            }
            else if (callMessage.IceUpdateMessages != null)
            {
                foreach (IceUpdateMessage u in callMessage.IceUpdateMessages)
                {
                    pushCallMessage.IceUpdate.Add(new CallMessage.Types.IceUpdate()
                    {
                        Id = u.Id,
                        Sdp = u.Sdp,
                        SdpMid = u.SdpMid,
                        SdpMLineIndex = u.SdpMLineIndex
                    });
                }
            }
            else if (callMessage.HangupMessage != null)
            {
                pushCallMessage.Hangup = new CallMessage.Types.Hangup()
                {
                    Id = callMessage.HangupMessage.Id
                };
            }
            else if (callMessage.BusyMessage != null)
            {
                pushCallMessage.Busy = new CallMessage.Types.Busy()
                {
                    Id = callMessage.BusyMessage.Id
                };
            }

            content.CallMessage = pushCallMessage;
            return content.ToByteArray();
        }

        private byte[] createMultiDeviceContactsContent(SignalServiceAttachmentStream contacts, bool complete)
        {
            Content content = new Content { };
            SyncMessage syncMessage = createSyncMessage();
            syncMessage.Contacts = new SyncMessage.Types.Contacts
            {
                Blob = createAttachmentPointer(contacts),
                Complete = complete
            };
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] createMultiDeviceGroupsContent(SignalServiceAttachmentStream groups)
        {
            Content content = new Content { };
            SyncMessage syncMessage = createSyncMessage();
            syncMessage.Groups = new SyncMessage.Types.Groups
            {
                Blob = createAttachmentPointer(groups)
            };
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] createMultiDeviceSentTranscriptContent(byte[] rawContent, May<SignalServiceAddress> recipient, ulong timestamp)
        {
            try
            {
                Content content = new Content { };
                SyncMessage syncMessage = createSyncMessage();
                SyncMessage.Types.Sent sentMessage = new SyncMessage.Types.Sent { };
                DataMessage dataMessage = DataMessage.Parser.ParseFrom(rawContent);

                sentMessage.Timestamp = timestamp;
                sentMessage.Message = dataMessage;

                if (recipient.HasValue)
                {
                    sentMessage.Destination = recipient.ForceGetValue().getNumber();
                }

                if (dataMessage.ExpireTimer > 0)
                {
                    sentMessage.ExpirationStartTimestamp = (ulong)Util.CurrentTimeMillis();
                }
                syncMessage.Sent = sentMessage;
                content.SyncMessage = syncMessage;
                return content.ToByteArray();
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new Exception(e.Message);
            }
        }

        private byte[] createMultiDeviceReadContent(List<ReadMessage> readMessages)
        {
            Content content = new Content { };
            SyncMessage syncMessage = createSyncMessage();

            foreach (ReadMessage readMessage in readMessages)
            {
                syncMessage.Read.Add(new SyncMessage.Types.Read
                {
                    Timestamp = (ulong)readMessage.getTimestamp(),
                    Sender = readMessage.getSender()
                });
            }
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] createMultiDeviceBlockedContent(BlockedListMessage blocked)
        {
            Content content = new Content { };
            SyncMessage syncMessage = new SyncMessage { };
            SyncMessage.Types.Blocked blockedMessage = new SyncMessage.Types.Blocked { };

            blockedMessage.Numbers.AddRange(blocked.getNumbers());
            syncMessage.Blocked = blockedMessage;
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] createMultiDeviceVerifiedContent(List<VerifiedMessage> verifiedMessages)
        {
            Content content = new Content { };
            SyncMessage syncMessage = createSyncMessage();

            foreach (VerifiedMessage verifiedMessage in verifiedMessages)
            {
                SyncMessage.Types.Verified verifiedMessageBuilder = new SyncMessage.Types.Verified { };
                verifiedMessageBuilder.Destination = verifiedMessage.Destination;
                verifiedMessageBuilder.IdentityKey = ByteString.CopyFrom(verifiedMessage.IdentityKey.serialize());

                switch (verifiedMessage.Verified)
                {
                    case VerifiedMessage.VerifiedState.Default:
                        verifiedMessageBuilder.State = SyncMessage.Types.Verified.Types.State.Default;
                        break;
                    case VerifiedMessage.VerifiedState.Verified:
                        verifiedMessageBuilder.State = SyncMessage.Types.Verified.Types.State.Verified;
                        break;
                    case VerifiedMessage.VerifiedState.Unverified:
                        verifiedMessageBuilder.State = SyncMessage.Types.Verified.Types.State.Unverified;
                        break;
                    default:
                        throw new Exception("Unknown: " + verifiedMessage.Verified);
                }

                syncMessage.Verified.Add(verifiedMessageBuilder);
            }

            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private SyncMessage createSyncMessage()
        {
            SyncMessage syncMessage = new SyncMessage { };
            syncMessage.Padding = ByteString.CopyFrom(Util.getSecretBytes(512));
            return syncMessage;
        }

        private GroupContext createGroupContent(SignalServiceGroup group)
        {
            GroupContext groupContext = new GroupContext { };
            groupContext.Id = ByteString.CopyFrom(group.GroupId);

            if (group.Type != SignalServiceGroup.GroupType.DELIVER)
            {
                if (group.Type == SignalServiceGroup.GroupType.UPDATE) groupContext.Type = GroupContext.Types.Type.Update;
                else if (group.Type == SignalServiceGroup.GroupType.QUIT) groupContext.Type = GroupContext.Types.Type.Quit;
                else if (group.Type == SignalServiceGroup.GroupType.REQUEST_INFO) groupContext.Type = GroupContext.Types.Type.RequestInfo;
                else throw new Exception("Unknown type: " + group.Type);

                if (group.Name != null) groupContext.Name = group.Name;
                if (group.Members != null ) groupContext.Members.AddRange(group.Members);

                if (group.Avatar != null && group.Avatar.isStream())
                {
                    AttachmentPointer pointer = createAttachmentPointer(group.Avatar.asStream());
                    groupContext.Avatar = pointer;
                }
            }
            else
            {
                groupContext.Type = GroupContext.Types.Type.Deliver;
            }

            return groupContext;
        }

        private SendMessageResponseList sendMessage(List<SignalServiceAddress> recipients, long timestamp, byte[] content)
        {
            SendMessageResponseList responseList = new SendMessageResponseList();
            foreach (SignalServiceAddress recipient in recipients)
            {
                try
                {
                    var response = sendMessage(recipient, timestamp, content, false);
                    responseList.AddResponse(response);
                }
                catch (UntrustedIdentityException e)
                {
                    Debug.WriteLine("untrusted identity: " + recipient, TAG);
                    responseList.UntrustedIdentities.Add(e);
                }
                catch (UnregisteredUserException e)
                {
                    Debug.WriteLine("unregistered user: " + recipient, TAG);
                    responseList.UnregisteredUsers.Add(e);
                }
                catch (PushNetworkException e)
                {
                    Debug.WriteLine("PushNetWorkException for:" + recipient, TAG);
                    responseList.NetworkExceptions.Add(new NetworkFailureException(recipient.getNumber(), e));
                }
            }
            return responseList;
        }

        private SendMessageResponse sendMessage(SignalServiceAddress recipient, long timestamp, byte[] content, bool silent)
        {
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    OutgoingPushMessageList messages = getEncryptedMessages(socket, recipient, timestamp, content, silent);
                    if (pipe != null)
                    {
                        try
                        {
                            Debug.WriteLine("Transmitting over pipe...");
                            return pipe.Send(messages);
                        }
                        catch (Exception e)
                        {
                            Debug.WriteLine(e.Message + " - falling back to new connection...");
                        }
                    }

                    Debug.WriteLine("Not transmitting over pipe...");
                    return socket.sendMessage(messages);
                }
                catch (MismatchedDevicesException mde)
                {
                    Debug.WriteLine("MismatchedDevicesException");
                    Debug.WriteLine(mde.Message);
                    Debug.WriteLine(mde.StackTrace);
                    handleMismatchedDevices(socket, recipient, mde.getMismatchedDevices());
                }
                catch (StaleDevicesException ste)
                {
                    Debug.WriteLine("MismatchedDevicesException");
                    Debug.WriteLine(ste.Message);
                    Debug.WriteLine(ste.StackTrace);
                    handleStaleDevices(recipient, ste.getStaleDevices());
                }
            }
            Debug.WriteLine("Failed to resolve conflicts after 3 attempts!");
            throw new Exception("Failed to resolve conflicts after 3 attempts!");
        }

        private IList<AttachmentPointer> createAttachmentPointers(List<SignalServiceAttachment> attachments)
        {
            IList<AttachmentPointer> pointers = new List<AttachmentPointer>();

            if (attachments == null || attachments.Count == 0)
            {
                Debug.WriteLine("No attachments present...", TAG);
                return pointers;
            }

            foreach (SignalServiceAttachment attachment in attachments)
            {
                if (attachment.isStream())
                {
                    Debug.WriteLine("Found attachment, creating pointer...", TAG);
                    pointers.Add(createAttachmentPointer(attachment.asStream()));
                }
            }

            return pointers;
        }

        private AttachmentPointer createAttachmentPointer(SignalServiceAttachmentStream attachment)
        {
            byte[] attachmentKey = Util.getSecretBytes(64);
            PushAttachmentData attachmentData = new PushAttachmentData(attachment.getContentType(),
                                                                       attachment.getInputStream(),
                                                                       (ulong)attachment.getLength(),
                                                                       attachmentKey);

            Tuple<ulong, byte[]> attachmentIdAndDigest = socket.SendAttachment(attachmentData);

            var attachmentPointer = new AttachmentPointer
            {
                ContentType = attachment.getContentType(),
                Id = attachmentIdAndDigest.Item1,
                Key = ByteString.CopyFrom(attachmentKey),
                Digest = ByteString.CopyFrom(attachmentIdAndDigest.Item2),
                Size = (uint)attachment.getLength()
            };

            if (attachment.FileName != null)
            {
                attachmentPointer.FileName = attachment.FileName;
            }

            if (attachment.getPreview().HasValue)
            {
                attachmentPointer.Thumbnail = ByteString.CopyFrom(attachment.getPreview().ForceGetValue());
            }

            if (attachment.VoiceNote)
            {
                attachmentPointer.Flags = (uint) AttachmentPointer.Types.Flags.VoiceMessage;
            }

            return attachmentPointer;
        }

        private OutgoingPushMessageList getEncryptedMessages(PushServiceSocket socket,
                                                   SignalServiceAddress recipient,
                                                   long timestamp,
                                                   byte[] plaintext,
                                                   bool silent)
        {
            List<OutgoingPushMessage> messages = new List<OutgoingPushMessage>();

            bool myself = recipient.Equals(localAddress);
            if (!myself || CredentialsProvider.GetDeviceId() != SignalServiceAddress.DEFAULT_DEVICE_ID)
            {
                messages.Add(getEncryptedMessage(socket, recipient, SignalServiceAddress.DEFAULT_DEVICE_ID, plaintext, silent));
            }

            foreach (uint deviceId in store.GetSubDeviceSessions(recipient.getNumber()))
            {
                if (!myself || deviceId != CredentialsProvider.GetDeviceId())
                {
                    if (store.ContainsSession(new SignalProtocolAddress(recipient.getNumber(), deviceId)))
                    {
                        messages.Add(getEncryptedMessage(socket, recipient, deviceId, plaintext, silent));
                    }
                }
            }

            return new OutgoingPushMessageList(recipient.getNumber(), (ulong)timestamp, recipient.getRelay().HasValue ? recipient.getRelay().ForceGetValue() : null, messages);
        }

        private OutgoingPushMessage getEncryptedMessage(PushServiceSocket socket, SignalServiceAddress recipient, uint deviceId, byte[] plaintext, bool silent)
        {
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipient.getNumber(), deviceId);
            SignalServiceCipher cipher = new SignalServiceCipher(localAddress, store);

            if (!store.ContainsSession(signalProtocolAddress))
            {
                try
                {
                    List<PreKeyBundle> preKeys = socket.getPreKeys(recipient, deviceId);

                    foreach (PreKeyBundle preKey in preKeys)
                    {
                        if (CredentialsProvider.GetUser().Equals(recipient.getNumber()) && CredentialsProvider.GetDeviceId() == preKey.getDeviceId())
                        {
                            continue;
                        }
                        try
                        {
                            SignalProtocolAddress preKeyAddress = new SignalProtocolAddress(recipient.getNumber(), preKey.getDeviceId());
                            SessionBuilder sessionBuilder = new SessionBuilder(store, preKeyAddress);
                            sessionBuilder.process(preKey);
                        }
                        catch (libsignal.exceptions.UntrustedIdentityException e)
                        {
                            throw new UntrustedIdentityException("Untrusted identity key!", recipient.getNumber(), preKey.getIdentityKey());
                        }
                    }

                    if (eventListener != null)
                    {
                        eventListener.onSecurityEvent(recipient);
                    }
                }
                catch (InvalidKeyException e)
                {
                    throw new Exception(e.Message);
                }
            }

            return cipher.encrypt(signalProtocolAddress, plaintext, silent);
        }

        private void handleMismatchedDevices(PushServiceSocket socket, SignalServiceAddress recipient, MismatchedDevices mismatchedDevices)
        {
            try
            {
                foreach (uint extraDeviceId in mismatchedDevices.getExtraDevices())
                {
                    store.DeleteSession(new SignalProtocolAddress(recipient.getNumber(), extraDeviceId));
                }

                foreach (uint missingDeviceId in mismatchedDevices.getMissingDevices())
                {
                    PreKeyBundle preKey = socket.getPreKey(recipient, missingDeviceId);

                    try
                    {
                        SessionBuilder sessionBuilder = new SessionBuilder(store, new SignalProtocolAddress(recipient.getNumber(), missingDeviceId));
                        sessionBuilder.process(preKey);
                    }
                    catch (libsignal.exceptions.UntrustedIdentityException e)
                    {
                        throw new UntrustedIdentityException("Untrusted identity key!", recipient.getNumber(), preKey.getIdentityKey());
                    }
                }
            }
            catch (InvalidKeyException e)
            {
                throw new Exception(e.Message);
            }
        }

        private void handleStaleDevices(SignalServiceAddress recipient, StaleDevices staleDevices)
        {
            foreach (uint staleDeviceId in staleDevices.getStaleDevices())
            {
                store.DeleteSession(new SignalProtocolAddress(recipient.getNumber(), staleDeviceId));
            }
        }

        private byte[] createSentTranscriptMessage(byte[] rawContent, May<SignalServiceAddress> recipient, ulong timestamp)
        {
            {
                try
                {
                    Content content = new Content { };
                    SyncMessage syncMessage = new SyncMessage { };
                    SyncMessage.Types.Sent sentMessage = new SyncMessage.Types.Sent { };

                    sentMessage.Timestamp = timestamp;
                    sentMessage.Message = DataMessage.Parser.ParseFrom(rawContent);

                    if (recipient.HasValue)
                    {
                        sentMessage.Destination = recipient.ForceGetValue().getNumber();
                    }
                    syncMessage.Sent = sentMessage;
                    content.SyncMessage = syncMessage;
                    return content.ToByteArray();
                }
                catch (InvalidProtocolBufferException e)
                {
                    throw new Exception(e.Message);
                }
            }
        }

        public interface EventListener
        {
            void onSecurityEvent(SignalServiceAddress address);
        }
    }
}
