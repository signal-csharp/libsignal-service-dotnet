using Google.Protobuf;
using libsignal;
using libsignal.state;
using libsignal_service_dotnet.messages.calls;
using libsignalservice.configuration;
using libsignalservice.crypto;
using libsignalservice.messages;
using libsignalservice.messages.multidevice;
using libsignalservice.push;
using libsignalservice.push.exceptions;
using libsignalservice.push.http;
using libsignalservice.util;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using static libsignalservice.messages.SignalServiceDataMessage;
using static libsignalservice.push.DataMessage.Types.Quote.Types;
using static libsignalservice.push.SyncMessage.Types;

namespace libsignalservice
{
    /// <summary>
    /// The main interface for sending Signal Service messages.
    /// </summary>
    public class SignalServiceMessageSender
    {
        private static readonly string TAG = "SignalServiceMessageSender";

        private readonly PushServiceSocket socket;
        private readonly SignalProtocolStore store;
        private readonly SignalServiceAddress localAddress;
        private readonly SignalServiceMessagePipe pipe;
        private readonly IEventListener eventListener;
        private readonly CancellationToken Token;
        private readonly StaticCredentialsProvider CredentialsProvider;

        /// <summary>
        /// Construct a SignalServiceMessageSender
        /// </summary>
        /// <param name="token">A CancellationToken to cancel the sender's operations</param>
        /// <param name="urls">The URL of the Signal Service.</param>
        /// <param name="user">The Signal Service username (eg phone number).</param>
        /// <param name="password">The Signal Service user password</param>
        /// <param name="deviceId">Tbe Signal Service device id</param>
        /// <param name="store">The SignalProtocolStore.</param>
        /// <param name="pipe">An optional SignalServiceMessagePipe</param>
        /// <param name="eventListener">An optional event listener, which fires whenever sessions are
        /// setup or torn down for a recipient.</param>
        /// <param name="userAgent"></param>
        public SignalServiceMessageSender(CancellationToken token, SignalServiceConfiguration urls,
                                       string user, string password, int deviceId,
                                       SignalProtocolStore store,
                                       SignalServiceMessagePipe pipe,
                                       IEventListener eventListener, string userAgent)
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
        /// <param name="token">The cancellation token</param>
        /// <param name="recipient">The sender of the received message you're acknowledging</param>
        /// <param name="message">The receipt message</param>
        public async Task SendDeliveryReceipt(CancellationToken token, SignalServiceAddress recipient, SignalServiceReceiptMessage message)
        {
            byte[] content = CreateReceiptContent(message);
            await SendMessage(token, recipient, message.When, content, true);
        }

        /// <summary>
        /// Send a call setup message to a single recipient
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="recipient">The message's destination</param>
        /// <param name="message">The call message</param>
        public async Task SendCallMessage(CancellationToken token, SignalServiceAddress recipient, SignalServiceCallMessage message)
        {
            byte[] content = CreateCallContent(message);
            await SendMessage(token, recipient, Util.CurrentTimeMillis(), content, true);
        }

        /// <summary>
        /// Send a message to a single recipient.
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="recipient">The message's destination.</param>
        /// <param name="message">The message.</param>
        public async Task SendMessage(CancellationToken token, SignalServiceAddress recipient, SignalServiceDataMessage message)
        {
            byte[] content = await CreateMessageContent(token, message);
            long timestamp = message.Timestamp;
            bool silent = message.Group != null && message.Group.Type == SignalServiceGroup.GroupType.REQUEST_INFO;
            var resp = await SendMessage(token, recipient, timestamp, content, silent);

            if (resp.NeedsSync)
            {
                byte[] syncMessage = CreateMultiDeviceSentTranscriptContent(content, new May<SignalServiceAddress>(recipient), (ulong)timestamp);
                await SendMessage(token, localAddress, timestamp, syncMessage, false);
            }

            if (message.EndSession)
            {
                store.DeleteAllSessions(recipient.E164number);

                if (eventListener != null)
                {
                    eventListener.OnSecurityEvent(recipient);
                }
            }
        }

        /// <summary>
        /// Send a message to a group.
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="recipients">The group members.</param>
        /// <param name="message">The group message.</param>
        public async Task SendMessage(CancellationToken token, List<SignalServiceAddress> recipients, SignalServiceDataMessage message)
        {
            byte[] content = await CreateMessageContent(token, message);
            long timestamp = message.Timestamp;
            SendMessageResponseList response = await SendMessage(token, recipients, timestamp, content);
            try
            {
                if (response != null && response.NeedsSync)
                {
                    byte[] syncMessage = CreateMultiDeviceSentTranscriptContent(content, May<SignalServiceAddress>.NoValue, (ulong)timestamp);
                    await SendMessage(token, localAddress, timestamp, syncMessage, false);
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

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="token"></param>
        /// <param name="message"></param>
        public async Task SendMessage(CancellationToken token, SignalServiceSyncMessage message)
        {
            byte[] content;

            if (message.Contacts != null)
            {
                content = await CreateMultiDeviceContactsContent(token, message.Contacts.Contacts.AsStream(),
                    message.Contacts.Complete);
            }
            else if (message.Groups != null)
            {
                content = await CreateMultiDeviceGroupsContent(token, message.Groups.AsStream());
            }
            else if (message.Reads != null)
            {
                content = CreateMultiDeviceReadContent(message.Reads);
            }
            else if (message.BlockedList != null)
            {
                content = CreateMultiDeviceBlockedContent(message.BlockedList);
            }
            else if (message.Configuration != null)
            {
                content = CreateMultiDeviceConfigurationContent(message.Configuration);
            }
            else if (message.Verified != null)
            {
                await SendMessage(token, message.Verified);
                return;
            }
            else if (message.Request != null)
            {
                content = CreateRequestContent(message.Request);
            }
            else
            {
                throw new Exception("Unsupported sync message!");
            }

            await SendMessage(token, localAddress, Util.CurrentTimeMillis(), content, false);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="soTimeoutMillis"></param>
        public void SetSoTimeoutMillis(long soTimeoutMillis)
        {
            socket.SetSoTimeoutMillis(soTimeoutMillis);
        }

        /// <summary>
        /// TODO
        /// </summary>
        public void CancelInFlightRequests()
        {
            socket.CancelInFlightRequests();
        }

        private async Task SendMessage(CancellationToken token, VerifiedMessage message)
        {
            byte[] nullMessageBody = new DataMessage()
            {
                Body = Base64.EncodeBytes(Util.GetRandomLengthBytes(140))
            }.ToByteArray();

            NullMessage nullMessage = new NullMessage()
            {
                Padding = ByteString.CopyFrom(nullMessageBody)
            };

            byte[] content = new Content()
            {
                NullMessage = nullMessage
            }.ToByteArray();

            SendMessageResponse response = await SendMessage(token, new SignalServiceAddress(message.Destination), message.Timestamp, content, false);

            if (response != null && response.NeedsSync)
            {
                byte[] syncMessage = CreateMultiDeviceVerifiedContent(message, nullMessage.ToByteArray());
                await SendMessage(token, localAddress, message.Timestamp, syncMessage, false);
            }
        }

        private byte[] CreateReceiptContent(SignalServiceReceiptMessage message)
        {
            Content content = new Content();
            ReceiptMessage receiptMessage = new ReceiptMessage();
            foreach (var timestamp in message.Timestamps)
            {
                receiptMessage.Timestamp.Add(timestamp);
            }

            if (message.IsDeliveryReceipt())
                receiptMessage.Type = ReceiptMessage.Types.Type.Delivery;
            else if (message.IsReadReceipt())
                receiptMessage.Type = ReceiptMessage.Types.Type.Read;

            content.ReceiptMessage = receiptMessage;
            return receiptMessage.ToByteArray();
        }

        private async Task<byte[]> CreateMessageContent(CancellationToken token, SignalServiceDataMessage message)// throws IOException
        {
            Content content = new Content();
            DataMessage dataMessage = new DataMessage { };
            IList<AttachmentPointer> pointers = await CreateAttachmentPointers(token, message.Attachments);

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
                dataMessage.Group = await CreateGroupContent(token, message.Group);
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

            if (message.ProfileKey != null)
            {
                dataMessage.ProfileKey = ByteString.CopyFrom(message.ProfileKey);
            }

            if (message.Quote != null)
            {
                var quote = new DataMessage.Types.Quote()
                {
                    Id = (ulong) message.Quote.Id,
                    Author = message.Quote.Author.E164number,
                    Text = message.Quote.Text
                };
                foreach (SignalServiceQuotedAttachment attachment in message.Quote.Attachments)
                {
                    QuotedAttachment protoAttachment = new QuotedAttachment()
                    {
                        ContentType = attachment.ContentType
                    };
                    if (attachment.FileName != null)
                    {
                        protoAttachment.FileName = attachment.FileName;
                    }

                    if (attachment.Thumbnail != null)
                    {
                        protoAttachment.Thumbnail = await CreateAttachmentPointer(token, attachment.Thumbnail.AsStream());
                    }
                    quote.Attachments.Add(protoAttachment);
                }
                dataMessage.Quote = quote;
            }

            dataMessage.Timestamp = (ulong) message.Timestamp;

            content.DataMessage = dataMessage;
            return content.ToByteArray();
        }

        private byte[] CreateCallContent(SignalServiceCallMessage callMessage)
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

        private async Task<byte[]> CreateMultiDeviceContactsContent(CancellationToken token, SignalServiceAttachmentStream contacts, bool complete)
        {
            Content content = new Content { };
            SyncMessage syncMessage = CreateSyncMessage();
            syncMessage.Contacts = new SyncMessage.Types.Contacts
            {
                Blob = await CreateAttachmentPointer(token, contacts),
                Complete = complete
            };
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private async Task<byte[]> CreateMultiDeviceGroupsContent(CancellationToken token, SignalServiceAttachmentStream groups)
        {
            Content content = new Content { };
            SyncMessage syncMessage = CreateSyncMessage();
            syncMessage.Groups = new SyncMessage.Types.Groups
            {
                Blob = await CreateAttachmentPointer(token, groups)
            };
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] CreateMultiDeviceSentTranscriptContent(byte[] rawContent, May<SignalServiceAddress> recipient, ulong timestamp)
        {
            try
            {
                Content content = new Content { };
                SyncMessage syncMessage = CreateSyncMessage();
                SyncMessage.Types.Sent sentMessage = new SyncMessage.Types.Sent { };
                DataMessage dataMessage = Content.Parser.ParseFrom(rawContent).DataMessage;

                sentMessage.Timestamp = timestamp;
                sentMessage.Message = dataMessage;

                if (recipient.HasValue)
                {
                    sentMessage.Destination = recipient.ForceGetValue().E164number;
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

        private byte[] CreateMultiDeviceReadContent(List<ReadMessage> readMessages)
        {
            Content content = new Content { };
            SyncMessage syncMessage = CreateSyncMessage();

            foreach (ReadMessage readMessage in readMessages)
            {
                syncMessage.Read.Add(new SyncMessage.Types.Read
                {
                    Timestamp = (ulong)readMessage.Timestamp,
                    Sender = readMessage.Sender
                });
            }
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] CreateRequestContent(RequestMessage request)
        {
            Content content = new Content { };
            SyncMessage syncMessage = CreateSyncMessage();

            syncMessage.Request = request.Request;
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] CreateMultiDeviceBlockedContent(BlockedListMessage blocked)
        {
            Content content = new Content { };
            SyncMessage syncMessage = new SyncMessage { };
            Blocked blockedMessage = new Blocked { };

            blockedMessage.Numbers.AddRange(blocked.Numbers);
            syncMessage.Blocked = blockedMessage;
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] CreateMultiDeviceConfigurationContent(ConfigurationMessage configurationMessage)
        {
            Content content = new Content { };
            SyncMessage syncMessage = CreateSyncMessage();
            Configuration configuration = new Configuration();

            if (configurationMessage.ReadReceipts != null)
            {
                configuration.ReadReceipts = configurationMessage.ReadReceipts.Value;
            }

            syncMessage.Configuration = configuration;
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] CreateMultiDeviceVerifiedContent(VerifiedMessage verifiedMessage, byte[] nullMessage)
        {
            Content content = new Content { };
            SyncMessage syncMessage = CreateSyncMessage();
            Verified verifiedMessageBuilder = new Verified
            {
                NullMessage = ByteString.CopyFrom(nullMessage),
                Destination = verifiedMessage.Destination,
                IdentityKey = ByteString.CopyFrom(verifiedMessage.IdentityKey.serialize())
            };

            switch (verifiedMessage.Verified)
            {
                case VerifiedMessage.VerifiedState.Default:
                    verifiedMessageBuilder.State = Verified.Types.State.Default;
                    break;
                case VerifiedMessage.VerifiedState.Verified:
                    verifiedMessageBuilder.State = Verified.Types.State.Verified;
                    break;
                case VerifiedMessage.VerifiedState.Unverified:
                    verifiedMessageBuilder.State = Verified.Types.State.Unverified;
                    break;
                default:
                    throw new Exception("Unknown: " + verifiedMessage.Verified);
            }

            syncMessage.Verified = verifiedMessageBuilder;
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private SyncMessage CreateSyncMessage()
        {
            SyncMessage syncMessage = new SyncMessage { };
            syncMessage.Padding = ByteString.CopyFrom(Util.GetRandomLengthBytes(512));
            return syncMessage;
        }

        private async Task<GroupContext> CreateGroupContent(CancellationToken token, SignalServiceGroup group)
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

                if (group.Avatar != null && group.Avatar.IsStream())
                {
                    AttachmentPointer pointer = await CreateAttachmentPointer(token, group.Avatar.AsStream());
                    groupContext.Avatar = pointer;
                }
            }
            else
            {
                groupContext.Type = GroupContext.Types.Type.Deliver;
            }

            return groupContext;
        }

        private async Task<SendMessageResponseList> SendMessage(CancellationToken token, List<SignalServiceAddress> recipients, long timestamp, byte[] content)
        {
            SendMessageResponseList responseList = new SendMessageResponseList();
            foreach (SignalServiceAddress recipient in recipients)
            {
                try
                {
                    var response = await SendMessage(token, recipient, timestamp, content, false);
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
                    responseList.NetworkExceptions.Add(new NetworkFailureException(recipient.E164number, e));
                }
            }
            return responseList;
        }

        private async Task<SendMessageResponse> SendMessage(CancellationToken token, SignalServiceAddress recipient, long timestamp, byte[] content, bool silent)
        {
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    OutgoingPushMessageList messages = await GetEncryptedMessages(token, socket, recipient, timestamp, content, silent);
                    if (pipe != null)
                    {
                        try
                        {
                            Debug.WriteLine("Transmitting over pipe...");
                            return await pipe.Send(messages);
                        }
                        catch (Exception e)
                        {
                            Debug.WriteLine(e.Message + " - falling back to new connection...");
                        }
                    }

                    Debug.WriteLine("Not transmitting over pipe...");
                    return await socket.SendMessage(token, messages);
                }
                catch (MismatchedDevicesException mde)
                {
                    await HandleMismatchedDevices(token, socket, recipient, mde.MismatchedDevices);
                }
                catch (StaleDevicesException ste)
                {
                    HandleStaleDevices(recipient, ste.StaleDevices);
                }
            }
            Debug.WriteLine("Failed to resolve conflicts after 3 attempts!");
            throw new Exception("Failed to resolve conflicts after 3 attempts!");
        }

        private async Task<IList<AttachmentPointer>> CreateAttachmentPointers(CancellationToken token, List<SignalServiceAttachment> attachments)
        {
            IList<AttachmentPointer> pointers = new List<AttachmentPointer>();

            if (attachments == null || attachments.Count == 0)
            {
                Debug.WriteLine("No attachments present...", TAG);
                return pointers;
            }

            foreach (SignalServiceAttachment attachment in attachments)
            {
                if (attachment.IsStream())
                {
                    Debug.WriteLine("Found attachment, creating pointer...", TAG);
                    pointers.Add(await CreateAttachmentPointer(token, attachment.AsStream()));
                }
                else if (attachment.IsPointer())
                {
                    pointers.Add(CreateAttachmentPointerFromPointer(attachment.AsPointer()));
                }
            }

            return pointers;
        }

        private async Task<AttachmentPointer> CreateAttachmentPointer(CancellationToken token, SignalServiceAttachmentStream attachment)
        {
            byte[] attachmentKey = Util.GetSecretBytes(64);
            long paddedLength = PaddingInputStream.GetPaddedSize(attachment.Length);
            long ciphertextLength = AttachmentCipherInputStream.GetCiphertextLength(paddedLength);
            PushAttachmentData attachmentData = new PushAttachmentData(attachment.ContentType,
                                                                       new PaddingInputStream(attachment.InputStream, attachment.Length),
                                                                       ciphertextLength,
                                                                       new AttachmentCipherOutputStreamFactory(attachmentKey),
                                                                       attachment.Listener);

            (ulong id, byte[] digest) = await socket.SendAttachment(token, attachmentData);

            var attachmentPointer = new AttachmentPointer
            {
                ContentType = attachment.ContentType,
                Id = id,
                Key = ByteString.CopyFrom(attachmentKey),
                Digest = ByteString.CopyFrom(digest),
                Size = (uint)attachment.Length
            };

            if (attachment.FileName != null)
            {
                attachmentPointer.FileName = attachment.FileName;
            }

            if (attachment.Preview != null)
            {
                attachmentPointer.Thumbnail = ByteString.CopyFrom(attachment.Preview);
            }

            if (attachment.Width > 0)
            {
                attachmentPointer.Width = (uint) attachment.Width;
            }

            if (attachment.Height > 0)
            {
                attachmentPointer.Height = (uint)attachment.Height;
            }

            if (attachment.VoiceNote)
            {
                attachmentPointer.Flags = (uint) AttachmentPointer.Types.Flags.VoiceMessage;
            }

            return attachmentPointer;
        }

        private AttachmentPointer CreateAttachmentPointerFromPointer(SignalServiceAttachmentPointer attachment)
        {
            var attachmentPointer = new AttachmentPointer()
            {
                ContentType = attachment.ContentType,
                Id = attachment.Id,
                Key = ByteString.CopyFrom(attachment.Key),
                Digest = ByteString.CopyFrom(attachment.Digest),
                Size = (uint)attachment.Size
            };

            if (attachment.FileName != null)
            {
                attachmentPointer.FileName = attachment.FileName;
            }

            if (attachment.VoiceNote)
            {
                attachmentPointer.Flags = (uint)AttachmentPointer.Types.Flags.VoiceMessage;
            }

            return attachmentPointer;
        }

        /// <summary>
        /// Gets a URL that can be used to upload an attachment
        /// </summary>
        /// <returns>The attachment ID and the URL</returns>
        public async Task<(ulong id, string location)> RetrieveAttachmentUploadUrl(CancellationToken token)
        {
            return await socket.RetrieveAttachmentUploadUrl(token);
        }

        /// <summary>
        /// Encrypts an attachment to be uploaded
        /// </summary>
        /// <param name="data">The data stream of the attachment</param>
        /// <param name="key">64 random bytes</param>
        /// <returns>The digest and the encrypted data</returns>
        public (byte[] digest, Stream encryptedData) EncryptAttachment(Stream data, byte[] key)
        {
            return socket.EncryptAttachment(data, key);
        }

        private async Task<OutgoingPushMessageList> GetEncryptedMessages(CancellationToken token,
            PushServiceSocket socket,
            SignalServiceAddress recipient,
            long timestamp,
            byte[] plaintext,
            bool silent)
        {
            List<OutgoingPushMessage> messages = new List<OutgoingPushMessage>();

            bool myself = recipient.Equals(localAddress);
            if (!myself || CredentialsProvider.DeviceId != SignalServiceAddress.DEFAULT_DEVICE_ID)
            {
                messages.Add(await GetEncryptedMessage(token, socket, recipient, SignalServiceAddress.DEFAULT_DEVICE_ID, plaintext, silent));
            }

            foreach (uint deviceId in store.GetSubDeviceSessions(recipient.E164number))
            {
                if (!myself || deviceId != CredentialsProvider.DeviceId)
                {
                    if (store.ContainsSession(new SignalProtocolAddress(recipient.E164number, deviceId)))
                    {
                        messages.Add(await GetEncryptedMessage(token, socket, recipient, deviceId, plaintext, silent));
                    }
                }
            }

            return new OutgoingPushMessageList(recipient.E164number, (ulong)timestamp, recipient.Relay, messages);
        }

        private async Task<OutgoingPushMessage> GetEncryptedMessage(CancellationToken token, PushServiceSocket socket, SignalServiceAddress recipient, uint deviceId, byte[] plaintext, bool silent)
        {
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipient.E164number, deviceId);
            SignalServiceCipher cipher = new SignalServiceCipher(localAddress, store);

            if (!store.ContainsSession(signalProtocolAddress))
            {
                try
                {
                    List<PreKeyBundle> preKeys = await socket.GetPreKeys(token, recipient, deviceId);

                    foreach (PreKeyBundle preKey in preKeys)
                    {
                        if (CredentialsProvider.User.Equals(recipient.E164number) && CredentialsProvider.DeviceId == preKey.getDeviceId())
                        {
                            continue;
                        }
                        try
                        {
                            SignalProtocolAddress preKeyAddress = new SignalProtocolAddress(recipient.E164number, preKey.getDeviceId());
                            SessionBuilder sessionBuilder = new SessionBuilder(store, preKeyAddress);
                            sessionBuilder.process(preKey);
                        }
                        catch (libsignal.exceptions.UntrustedIdentityException)
                        {
                            throw new UntrustedIdentityException("Untrusted identity key!", recipient.E164number, preKey.getIdentityKey());
                        }
                    }

                    if (eventListener != null)
                    {
                        eventListener.OnSecurityEvent(recipient);
                    }
                }
                catch (InvalidKeyException e)
                {
                    throw new Exception(e.Message);
                }
            }

            try
            {
                return cipher.Encrypt(signalProtocolAddress, plaintext, silent);
            }
            catch(libsignal.exceptions.UntrustedIdentityException e)
            {
                throw new UntrustedIdentityException("Untrusted on send", e.getName(), e.getUntrustedIdentity());
            }
        }

        private async Task HandleMismatchedDevices(CancellationToken token, PushServiceSocket socket, SignalServiceAddress recipient, MismatchedDevices mismatchedDevices)
        {
            try
            {
                foreach (uint extraDeviceId in mismatchedDevices.ExtraDevices)
                {
                    store.DeleteSession(new SignalProtocolAddress(recipient.E164number, extraDeviceId));
                }

                foreach (uint missingDeviceId in mismatchedDevices.MissingDevices)
                {
                    PreKeyBundle preKey = await socket.GetPreKey(token, recipient, missingDeviceId);

                    try
                    {
                        SessionBuilder sessionBuilder = new SessionBuilder(store, new SignalProtocolAddress(recipient.E164number, missingDeviceId));
                        sessionBuilder.process(preKey);
                    }
                    catch (libsignal.exceptions.UntrustedIdentityException)
                    {
                        throw new UntrustedIdentityException("Untrusted identity key!", recipient.E164number, preKey.getIdentityKey());
                    }
                }
            }
            catch (InvalidKeyException e)
            {
                throw new Exception(e.Message);
            }
        }

        private void HandleStaleDevices(SignalServiceAddress recipient, StaleDevices staleDevices)
        {
            foreach (uint staleDeviceId in staleDevices.Devices)
            {
                store.DeleteSession(new SignalProtocolAddress(recipient.E164number, staleDeviceId));
            }
        }

        private byte[] CreateSentTranscriptMessage(byte[] rawContent, May<SignalServiceAddress> recipient, ulong timestamp)
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
                        sentMessage.Destination = recipient.ForceGetValue().E164number;
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

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        public interface IEventListener
        {
            void OnSecurityEvent(SignalServiceAddress address);
        }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
