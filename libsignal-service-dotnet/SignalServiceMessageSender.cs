using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Google.Protobuf;
using libsignal;
using libsignal.state;
using libsignal_service_dotnet.messages.calls;
using libsignalservice.configuration;
using libsignalservice.crypto;
using libsignalservice.messages;
using libsignalservice.messages.multidevice;
using libsignalservice.messages.shared;
using libsignalservice.push;
using libsignalservice.push.exceptions;
using libsignalservice.push.http;
using libsignalservice.util;
using libsignalservicedotnet.crypto;
using libsignalservicedotnet.messages;
using Microsoft.Extensions.Logging;
using static libsignalservice.messages.SignalServiceDataMessage;
using static libsignalservice.push.DataMessage.Types;
using static libsignalservice.push.DataMessage.Types.Quote.Types;
using static libsignalservice.push.SyncMessage.Types;

namespace libsignalservice
{
    /// <summary>
    /// The main interface for sending Signal Service messages.
    /// </summary>
    public class SignalServiceMessageSender
    {
        private readonly ILogger Logger = LibsignalLogging.CreateLogger<SignalServiceMessageSender>();

        private readonly PushServiceSocket Socket;
        private readonly SignalProtocolStore Store;
        private readonly SignalServiceAddress LocalAddress;
        private readonly IEventListener EventListener;
        private readonly CancellationToken Token;
        private readonly StaticCredentialsProvider CredentialsProvider;

        private readonly SignalServiceMessagePipe? Pipe;
        private readonly SignalServiceMessagePipe? UnidentifiedPipe;
        private bool IsMultiDevice;

        /// <summary>
        /// Construct a SignalServiceMessageSender
        /// </summary>
        /// <param name="token">A CancellationToken to cancel the sender's operations</param>
        /// <param name="urls">The URL of the Signal Service.</param>
        /// <param name="user">The Signal Service username (eg phone number).</param>
        /// <param name="password">The Signal Service user password</param>
        /// <param name="deviceId">The Signal Service device id</param>
        /// <param name="store">The SignalProtocolStore.</param>
        /// <param name="pipe">An optional SignalServiceMessagePipe</param>
        /// <param name="unidentifiedPipe"></param>
        /// <param name="eventListener">An optional event listener, which fires whenever sessions are
        /// setup or torn down for a recipient.</param>
        /// <param name="userAgent"></param>
        /// <param name="isMultiDevice"></param>
        public SignalServiceMessageSender(CancellationToken token, SignalServiceConfiguration urls,
                                       string user, string password, int deviceId,
                                       SignalProtocolStore store,
                                       string userAgent,
                                       HttpClient httpClient,
                                       bool isMultiDevice,
                                       SignalServiceMessagePipe? pipe,
                                       SignalServiceMessagePipe? unidentifiedPipe,
                                       IEventListener eventListener)
        {
            Token = token;
            CredentialsProvider = new StaticCredentialsProvider(user, password, deviceId);
            Socket = new PushServiceSocket(urls, CredentialsProvider, userAgent, httpClient);
            Store = store;
            LocalAddress = new SignalServiceAddress(user);
            Pipe = pipe;
            UnidentifiedPipe = unidentifiedPipe;
            IsMultiDevice = isMultiDevice;
            EventListener = eventListener;
        }

        /// <summary>
        /// Send a read receipt for a received message.
        /// </summary>
        /// <param name="recipient">The sender of the received message you're acknowledging.</param>
        /// <param name="unidentifiedAccess"></param>
        /// <param name="message">The read receipt to deliver.</param>
        /// <exception cref="IOException"></exception>
        /// <exception cref="UntrustedIdentityException"></exception>
        public async Task SendReceiptAsync(SignalServiceAddress recipient,
            UnidentifiedAccessPair? unidentifiedAccess,
            SignalServiceReceiptMessage message,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            byte[] content = CreateReceiptContent(message);
            await SendMessageAsync(recipient, GetTargetUnidentifiedAccess(unidentifiedAccess), message.When, content, false, token);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="recipient"></param>
        /// <param name="unidentifiedAccess"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        /// <exception cref="UntrustedIdentityException"></exception>
        public async Task SendTypingAsync(SignalServiceAddress recipient,
            UnidentifiedAccessPair? unidentifiedAccess,
            SignalServiceTypingMessage message,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            byte[] content = CreateTypingContent(message);

            await SendMessageAsync(recipient, GetTargetUnidentifiedAccess(unidentifiedAccess), message.Timestamp, content, true, token);
        }

        public async Task SendTypingAsync(List<SignalServiceAddress> recipients,
            List<UnidentifiedAccessPair?> unidentifiedAccess,
            SignalServiceTypingMessage message,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            byte[] content = CreateTypingContent(message);
            await SendMessageAsync(recipients, GetTargetUnidentifiedAccess(unidentifiedAccess), message.Timestamp, content, true, token);
        }

        /// <summary>
        /// Send a call setup message to a single recipient
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="recipient">The message's destination</param>
        /// <param name="unidentifiedAccess"></param>
        /// <param name="message">The call message</param>
        public async Task SendCallMessage(CancellationToken token, SignalServiceAddress recipient,
            UnidentifiedAccessPair? unidentifiedAccess, SignalServiceCallMessage message)
        {
            byte[] content = CreateCallContent(message);
            await SendMessageAsync(recipient, unidentifiedAccess?.TargetUnidentifiedAccess, Util.CurrentTimeMillis(), content, false, token);
        }

        /// <summary>
        /// Send a message to a single recipient.
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="recipient">The message's destination.</param>
        /// <param name="unidentifiedAccess"></param>
        /// <param name="message">The message.</param>
        /// <exception cref="UntrustedIdentityException"></exception>
        /// <exception cref="IOException"></exception>
        public async Task<SendMessageResult> SendMessage(CancellationToken token,
            SignalServiceAddress recipient,
            UnidentifiedAccessPair? unidentifiedAccess,
            SignalServiceDataMessage message)
        {
            byte[] content = await CreateMessageContentAsync(message, token);
            long timestamp = message.Timestamp;
            SendMessageResult result = await SendMessageAsync(recipient, unidentifiedAccess?.TargetUnidentifiedAccess, timestamp, content, false, token);

            if ((result.Success != null && result.Success.NeedsSync) || (unidentifiedAccess != null && IsMultiDevice))
            {
                byte[] syncMessage = CreateMultiDeviceSentTranscriptContent(content, recipient, (ulong)timestamp, new List<SendMessageResult>() { result });
                await SendMessageAsync(LocalAddress, unidentifiedAccess?.SelfUnidentifiedAccess, timestamp, syncMessage, false, token);
            }

            if (message.EndSession)
            {
                Store.DeleteAllSessions(recipient.E164number);

                if (EventListener != null)
                {
                    EventListener.OnSecurityEvent(recipient);
                }
            }
            return result;
        }

        /// <summary>
        /// Send a message to a group.
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="recipients">The group members.</param>
        /// <param name="unidentifiedAccess"></param>
        /// <param name="message">The group message.</param>
        public async Task<List<SendMessageResult>> SendMessage(CancellationToken token,
            List<SignalServiceAddress> recipients,
            List<UnidentifiedAccessPair?> unidentifiedAccess,
            SignalServiceDataMessage message)
        {
            byte[] content = await CreateMessageContentAsync(message, token);
            long timestamp = message.Timestamp;
            List<SendMessageResult> results = await SendMessageAsync(recipients, GetTargetUnidentifiedAccess(unidentifiedAccess), timestamp, content, false, token);
            bool needsSyncInResults = false;

            foreach (var result in results)
            {
                if (result.Success != null && result.Success.NeedsSync)
                {
                    needsSyncInResults = true;
                    break;
                }
            }
            if (needsSyncInResults || IsMultiDevice)
            {
                byte[] syncMessage = CreateMultiDeviceSentTranscriptContent(content, null, (ulong) timestamp, results);
                await SendMessageAsync(LocalAddress, null, timestamp, syncMessage, false, token);
            }
            return results;
        }

        public async Task<SignalServiceAttachmentPointer> UploadAttachmentAsync(SignalServiceAttachmentStream attachment,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            byte[] attachmentKey = Util.GetSecretBytes(64);
            long paddedLength = PaddingInputStream.GetPaddedSize(attachment.Length);
            long ciphertextLength = AttachmentCipherInputStream.GetCiphertextLength(paddedLength);
            PushAttachmentData attachmentData = new PushAttachmentData(attachment.ContentType,
                                                                       new PaddingInputStream(attachment.InputStream, attachment.Length),
                                                                       ciphertextLength,
                                                                       new AttachmentCipherOutputStreamFactory(attachmentKey),
                                                                       attachment.Listener);

            (ulong id, byte[] digest) = await Socket.SendAttachment(token.Value, attachmentData);

            return new SignalServiceAttachmentPointer(id,
                attachment.ContentType,
                attachmentKey,
                (uint)Util.ToIntExact(attachment.Length),
                attachment.Preview,
                attachment.Width, attachment.Height,
                digest,
                attachment.FileName,
                attachment.VoiceNote,
                attachment.Caption);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <param name="message"></param>
        /// <param name="unidenfifiedAccess"></param>
        /// <exception cref=""></exception>
        public async Task SendMessage(CancellationToken token, SignalServiceSyncMessage message, UnidentifiedAccessPair? unidenfifiedAccess)
        {
            byte[] content;

            if (message.Contacts != null)
            {
                content = await CreateMultiDeviceContactsContentAsync(message.Contacts.Contacts.AsStream(),
                    message.Contacts.Complete,
                    token);
            }
            else if (message.Groups != null)
            {
                content = await CreateMultiDeviceGroupsContentAsync(message.Groups.AsStream(), token);
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
            else if (message.Sent != null)
            {
                content = await CreateMultiDeviceSentTranscriptContentAsync(message.Sent, unidenfifiedAccess, token);
            }
            else if (message.Verified != null)
            {
                await SendMessageAsync(message.Verified, unidenfifiedAccess, token);
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

            await SendMessageAsync(LocalAddress, unidenfifiedAccess?.SelfUnidentifiedAccess, Util.CurrentTimeMillis(), content, false, token);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="soTimeoutMillis"></param>
        public void SetSoTimeoutMillis(long soTimeoutMillis)
        {
            Socket.SetSoTimeoutMillis(soTimeoutMillis);
        }

        /// <summary>
        /// 
        /// </summary>
        public void CancelInFlightRequests()
        {
            Socket.CancelInFlightRequests();
        }

        private async Task SendMessageAsync(VerifiedMessage message, UnidentifiedAccessPair? unidentifiedAccessPair, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

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

            SendMessageResult result = await SendMessageAsync(new SignalServiceAddress(message.Destination), unidentifiedAccessPair?.TargetUnidentifiedAccess, message.Timestamp, content, false, token);

            if (result.Success.NeedsSync)
            {
                byte[] syncMessage = CreateMultiDeviceVerifiedContent(message, nullMessage.ToByteArray());
                await SendMessageAsync(LocalAddress, unidentifiedAccessPair?.SelfUnidentifiedAccess, message.Timestamp, syncMessage, false, token);
            }
        }

        private byte[] CreateTypingContent(SignalServiceTypingMessage message)
        {
            Content content = new Content();
            TypingMessage typingMessage = new TypingMessage();

            typingMessage.Timestamp = (ulong)message.Timestamp;

            if (message.IsTypingStarted()) typingMessage.Action = TypingMessage.Types.Action.Started;
            else if (message.IsTypingStopped()) typingMessage.Action = TypingMessage.Types.Action.Stopped;
            else throw new ArgumentException("Unknown typing indicator");

            if (message.GroupId != null)
            {
                typingMessage.GroupId = ByteString.CopyFrom(message.GroupId);
            }

            content.TypingMessage = typingMessage;
            return content.ToByteArray();
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
            return content.ToByteArray();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        private async Task<byte[]> CreateMessageContentAsync(SignalServiceDataMessage message,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            Content content = new Content();
            DataMessage dataMessage = new DataMessage { };
            IList<AttachmentPointer> pointers = await CreateAttachmentPointersAsync(message.Attachments, token);

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
                dataMessage.Group = await CreateGroupContentAsync(message.Group, token);
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
                    Id = (ulong)message.Quote.Id,
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
                        protoAttachment.Thumbnail = await CreateAttachmentPointerAsync(attachment.Thumbnail.AsStream(), token);
                    }
                    quote.Attachments.Add(protoAttachment);
                }
                dataMessage.Quote = quote;
            }

            if (message.SharedContacts != null)
                dataMessage.Contact.AddRange(await CreateSharedContactContentAsync(message.SharedContacts, token));

            dataMessage.Timestamp = (ulong)message.Timestamp;

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

        private async Task<byte[]> CreateMultiDeviceContactsContentAsync(SignalServiceAttachmentStream contacts, bool complete,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            Content content = new Content { };
            SyncMessage syncMessage = CreateSyncMessage();
            syncMessage.Contacts = new SyncMessage.Types.Contacts
            {
                Blob = await CreateAttachmentPointerAsync(contacts, token),
                Complete = complete
            };
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private async Task<byte[]> CreateMultiDeviceGroupsContentAsync(SignalServiceAttachmentStream groups,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            Content content = new Content { };
            SyncMessage syncMessage = CreateSyncMessage();
            syncMessage.Groups = new SyncMessage.Types.Groups
            {
                Blob = await CreateAttachmentPointerAsync(groups, token)
            };
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private async Task<byte[]> CreateMultiDeviceSentTranscriptContentAsync(SentTranscriptMessage transcript, UnidentifiedAccessPair? unidentifiedAccess,
            CancellationToken? token = null)
        {
            SignalServiceAddress address = new SignalServiceAddress(transcript.Destination!);
            SendMessageResult result = SendMessageResult.NewSuccess(address, unidentifiedAccess != null, true);

            return CreateMultiDeviceSentTranscriptContent(await CreateMessageContentAsync(transcript.Message, token),
                address,
                (ulong)transcript.Timestamp,
                new List<SendMessageResult>() { result });
        }

        private byte[] CreateMultiDeviceSentTranscriptContent(byte[] rawContent, SignalServiceAddress? recipient, ulong timestamp, List<SendMessageResult> sendMessageResults)
        {
            try
            {
                Content content = new Content { };
                SyncMessage syncMessage = CreateSyncMessage();
                SyncMessage.Types.Sent sentMessage = new SyncMessage.Types.Sent { };
                DataMessage dataMessage = Content.Parser.ParseFrom(rawContent).DataMessage;

                sentMessage.Timestamp = timestamp;
                sentMessage.Message = dataMessage;

                foreach (var result in sendMessageResults)
                {
                    if (result.Success != null)
                    {
                        sentMessage.UnidentifiedStatus.Add(new Sent.Types.UnidentifiedDeliveryStatus()
                        {
                            Destination = result.Address.E164number,
                            Unidentified = result.Success.Unidentified
                        });
                    }
                }

                if (recipient != null)
                {
                    sentMessage.Destination = recipient.E164number;
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
            foreach (var groupId in blocked.GroupIds)
            {
                blockedMessage.GroupIds.Add(ByteString.CopyFrom(groupId));
            }
            syncMessage.Blocked = blockedMessage;
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] CreateMultiDeviceConfigurationContent(ConfigurationMessage configuration)
        {
            Content content = new Content { };
            SyncMessage syncMessage = CreateSyncMessage();
            Configuration configurationMessage = new Configuration();

            if (configuration.ReadReceipts != null)
            {
                configurationMessage.ReadReceipts = configuration.ReadReceipts.Value;
            }

            if (configuration.UnidentifiedDeliveryIndicators is bool unidentifiedDeliveryIndicators)
            {
                configurationMessage.UnidentifiedDeliveryIndicators = unidentifiedDeliveryIndicators;
            }

            if (configuration.TypingIndicators.HasValue)
            {
                configurationMessage.TypingIndicators = configuration.TypingIndicators.Value;
            }

            syncMessage.Configuration = configurationMessage;
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

        private async Task<GroupContext> CreateGroupContentAsync(SignalServiceGroup group,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            GroupContext groupContext = new GroupContext { };
            groupContext.Id = ByteString.CopyFrom(group.GroupId);

            if (group.Type != SignalServiceGroup.GroupType.DELIVER)
            {
                if (group.Type == SignalServiceGroup.GroupType.UPDATE) groupContext.Type = GroupContext.Types.Type.Update;
                else if (group.Type == SignalServiceGroup.GroupType.QUIT) groupContext.Type = GroupContext.Types.Type.Quit;
                else if (group.Type == SignalServiceGroup.GroupType.REQUEST_INFO) groupContext.Type = GroupContext.Types.Type.RequestInfo;
                else throw new Exception("Unknown type: " + group.Type);

                if (group.Name != null) groupContext.Name = group.Name;
                if (group.Members != null) groupContext.Members.AddRange(group.Members);

                if (group.Avatar != null && group.Avatar.IsStream())
                {
                    AttachmentPointer pointer = await CreateAttachmentPointerAsync(group.Avatar.AsStream(), token);
                    groupContext.Avatar = pointer;
                }
            }
            else
            {
                groupContext.Type = GroupContext.Types.Type.Deliver;
            }

            return groupContext;
        }

        private async Task<List<Contact>> CreateSharedContactContentAsync(List<SharedContact> contacts,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            List<Contact> results = new List<Contact>();

            foreach (SharedContact contact in contacts)
            {
                Contact.Types.Name nameBuilder = new Contact.Types.Name();
                if (contact.Name.Family != null) nameBuilder.FamilyName = contact.Name.Family;
                if (contact.Name.Given != null) nameBuilder.GivenName = contact.Name.Given;
                if (contact.Name.Middle != null) nameBuilder.MiddleName = contact.Name.Middle;
                if (contact.Name.Prefix != null) nameBuilder.Prefix = contact.Name.Prefix;
                if (contact.Name.Suffix != null) nameBuilder.Suffix = contact.Name.Suffix;
                if (contact.Name.Display != null) nameBuilder.DisplayName = contact.Name.Display;

                Contact contactBuilder = new Contact()
                {
                    Name = nameBuilder
                };

                if (contact.Address != null)
                {
                    foreach (PostalAddress address in contact.Address)
                    {
                        Contact.Types.PostalAddress addressBuilder = new Contact.Types.PostalAddress();

                        addressBuilder.Type = address.Type switch
                        {
                            PostalAddress.PostalAddressType.HOME => Contact.Types.PostalAddress.Types.Type.Home,
                            PostalAddress.PostalAddressType.WORK => Contact.Types.PostalAddress.Types.Type.Work,
                            PostalAddress.PostalAddressType.CUSTOM => Contact.Types.PostalAddress.Types.Type.Custom,
                            _ => throw new ArgumentException($"Unknown type: {address.Type}")
                        };

                        if (address.City != null) addressBuilder.City = address.City;
                        if (address.Country != null) addressBuilder.Country = address.Country;
                        if (address.Label != null) addressBuilder.Label = address.Label;
                        if (address.Neighborhood != null) addressBuilder.Neighborhood = address.Neighborhood;
                        if (address.Pobox != null) addressBuilder.Pobox = address.Pobox;
                        if (address.Postcode != null) addressBuilder.Postcode = address.Postcode;
                        if (address.Region != null) addressBuilder.Region = address.Region;
                        if (address.Street != null) addressBuilder.Street = address.Street;

                        contactBuilder.Address.Add(addressBuilder);
                    }
                }

                if (contact.Email != null)
                {
                    foreach (Email email in contact.Email)
                    {
                        Contact.Types.Email emailBuilder = new Contact.Types.Email()
                        {
                            Value = email.Value
                        };

                        emailBuilder.Type = email.Type switch
                        {
                            Email.EmailType.HOME => Contact.Types.Email.Types.Type.Home,
                            Email.EmailType.WORK => Contact.Types.Email.Types.Type.Work,
                            Email.EmailType.MOBILE => Contact.Types.Email.Types.Type.Mobile,
                            Email.EmailType.CUSTOM => Contact.Types.Email.Types.Type.Custom,
                            _ => throw new ArgumentException($"Unknown type {email.Type}")
                        };

                        if (email.Label != null) emailBuilder.Label = email.Label;

                        contactBuilder.Email.Add(emailBuilder);
                    }
                }

                if (contact.Phone != null)
                {
                    foreach (Phone phone in contact.Phone)
                    {
                        Contact.Types.Phone phoneBuilder = new Contact.Types.Phone()
                        {
                            Value = phone.Value
                        };

                        phoneBuilder.Type = phone.Type switch
                        {
                            Phone.PhoneType.HOME => Contact.Types.Phone.Types.Type.Home,
                            Phone.PhoneType.WORK => Contact.Types.Phone.Types.Type.Work,
                            Phone.PhoneType.MOBILE => Contact.Types.Phone.Types.Type.Mobile,
                            Phone.PhoneType.CUSTOM => Contact.Types.Phone.Types.Type.Custom,
                            _ => throw new ArgumentException($"Unknown type: {phone.Type}")
                        };

                        if (phone.Label != null) phoneBuilder.Label = phone.Label;

                        contactBuilder.Number.Add(phoneBuilder);
                    }
                }

                if (contact.Avatar != null)
                {
                    contactBuilder.Avatar = new Contact.Types.Avatar()
                    {
                        Avatar_ = await CreateAttachmentPointerAsync(contact.Avatar.Attachment.AsStream(), token),
                        IsProfile = contact.Avatar.IsProfile
                    };
                }

                if (contact.Organization != null)
                {
                    contactBuilder.Organization = contact.Organization;
                }

                results.Add(contactBuilder);
            }

            return results;
        }

        private async Task<List<SendMessageResult>> SendMessageAsync(List<SignalServiceAddress> recipients,
            List<UnidentifiedAccess?> unidentifiedAccess,
            long timestamp,
            byte[] content,
            bool online,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            List<SendMessageResult> results = new List<SendMessageResult>();
            var recipientsIterator = recipients.GetEnumerator();
            var unidentifiedAccessIterator = unidentifiedAccess.GetEnumerator();

            while (recipientsIterator.MoveNext())
            {
                unidentifiedAccessIterator.MoveNext();
                SignalServiceAddress recipient = recipientsIterator.Current;

                try
                {
                    SendMessageResult result = await SendMessageAsync(recipient, unidentifiedAccessIterator.Current, timestamp, content, online, token);
                    results.Add(result);
                }
                catch (UntrustedIdentityException ex)
                {
                    Logger.LogError(new EventId(), ex, "");
                    results.Add(SendMessageResult.NewIdentityFailure(recipient, ex.IdentityKey));
                }
                catch (UnregisteredUserException ex)
                {
                    Logger.LogError(new EventId(), ex, "");
                    results.Add(SendMessageResult.NewUnregisteredFailure(recipient));
                }
                catch (PushNetworkException ex)
                {
                    Logger.LogError(new EventId(), ex, "");
                    results.Add(SendMessageResult.NewNetworkFailure(recipient));
                }
            }

            return results;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="recipient"></param>
        /// <param name="unidentifiedAccess"></param>
        /// <param name="timestamp"></param>
        /// <param name="content"></param>
        /// <param name="online"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="UntrustedIdentityException"></exception>
        /// <exception cref="IOException"></exception>
        private async Task<SendMessageResult> SendMessageAsync(SignalServiceAddress recipient,
            UnidentifiedAccess? unidentifiedAccess,
            long timestamp,
            byte[] content,
            bool online,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            for (int i = 0; i < 4; i++)
            {
                try
                {
                    OutgoingPushMessageList messages = await GetEncryptedMessages(token.Value, Socket, recipient, unidentifiedAccess, timestamp, content, online);
                    var pipe = Pipe;
                    var unidentifiedPipe = UnidentifiedPipe;
                    if (Pipe != null && unidentifiedAccess == null)
                    {
                        try
                        {
                            Logger.LogTrace("Transmitting over pipe...");
                            var response = await Pipe.Send(messages, null);
                            return SendMessageResult.NewSuccess(recipient, false, response.NeedsSync);
                        }
                        catch (Exception e)
                        {
                            Logger.LogWarning(e.Message + " - falling back to new connection...");
                        }
                    }
                    else if (unidentifiedPipe != null && unidentifiedAccess != null)
                    {
                        var response = await unidentifiedPipe.Send(messages, unidentifiedAccess);
                        return SendMessageResult.NewSuccess(recipient, true, response.NeedsSync);
                    }

                    Logger.LogTrace("Not transmitting over pipe...");
                    SendMessageResponse resp = await Socket.SendMessage(messages, unidentifiedAccess, token);
                    return SendMessageResult.NewSuccess(recipient, unidentifiedAccess != null, resp.NeedsSync);
                }
                catch (MismatchedDevicesException mde)
                {
                    await HandleMismatchedDevices(token.Value, Socket, recipient, mde.MismatchedDevices);
                }
                catch (StaleDevicesException ste)
                {
                    HandleStaleDevices(recipient, ste.StaleDevices);
                }
            }
            Logger.LogError("Failed to resolve conflicts after 3 attempts!");
            throw new Exception("Failed to resolve conflicts after 3 attempts!");
        }

        private async Task<IList<AttachmentPointer>> CreateAttachmentPointersAsync(List<SignalServiceAttachment>? attachments,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            IList<AttachmentPointer> pointers = new List<AttachmentPointer>();

            if (attachments == null || attachments.Count == 0)
            {
                Logger.LogTrace("No attachments present...");
                return pointers;
            }

            foreach (SignalServiceAttachment attachment in attachments)
            {
                if (attachment.IsStream())
                {
                    Logger.LogTrace("Found attachment, creating pointer...");
                    pointers.Add(await CreateAttachmentPointerAsync(attachment.AsStream(), token));
                }
                else if (attachment.IsPointer())
                {
                    Logger.LogTrace("Including existing attachment pointer...");
                    pointers.Add(CreateAttachmentPointerFromPointer(attachment.AsPointer()));
                }
            }

            return pointers;
        }

        private AttachmentPointer CreateAttachmentPointer(SignalServiceAttachmentPointer attachment)
        {
            var attachmentPointer = new AttachmentPointer
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

            if (attachment.Preview != null)
            {
                attachmentPointer.Thumbnail = ByteString.CopyFrom(attachment.Preview);
            }

            if (attachment.Width > 0)
            {
                attachmentPointer.Width = (uint)attachment.Width;
            }

            if (attachment.Height > 0)
            {
                attachmentPointer.Height = (uint)attachment.Height;
            }

            if (attachment.VoiceNote)
            {
                attachmentPointer.Flags = (uint)AttachmentPointer.Types.Flags.VoiceMessage;
            }

            if (attachment.Caption != null)
            {
                attachmentPointer.Caption = attachment.Caption;
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
            return await Socket.RetrieveAttachmentUploadUrl(token);
        }

        /// <summary>
        /// Encrypts an attachment to be uploaded
        /// </summary>
        /// <param name="data">The data stream of the attachment</param>
        /// <param name="key">64 random bytes</param>
        /// <returns>The digest and the encrypted data</returns>
        public (byte[] digest, Stream encryptedData) EncryptAttachment(Stream data, byte[] key)
        {
            return Socket.EncryptAttachment(data, key);
        }

        private async Task<AttachmentPointer> CreateAttachmentPointerAsync(SignalServiceAttachmentStream attachment,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            SignalServiceAttachmentPointer pointer = await UploadAttachmentAsync(attachment, token);
            return CreateAttachmentPointer(pointer);
        }

        private async Task<OutgoingPushMessageList> GetEncryptedMessages(CancellationToken token,
            PushServiceSocket socket,
            SignalServiceAddress recipient,
            UnidentifiedAccess? unidentifiedAccess,
            long timestamp,
            byte[] plaintext,
            bool online)
        {
            List<OutgoingPushMessage> messages = new List<OutgoingPushMessage>();

            bool myself = recipient.Equals(LocalAddress);
            if (!myself || CredentialsProvider.DeviceId != SignalServiceAddress.DEFAULT_DEVICE_ID || unidentifiedAccess != null)
            {
                messages.Add(await GetEncryptedMessage(token, socket, recipient, unidentifiedAccess, SignalServiceAddress.DEFAULT_DEVICE_ID, plaintext));
            }

            foreach (uint deviceId in Store.GetSubDeviceSessions(recipient.E164number))
            {
                if (!myself || deviceId != CredentialsProvider.DeviceId)
                {
                    if (Store.ContainsSession(new SignalProtocolAddress(recipient.E164number, deviceId)))
                    {
                        messages.Add(await GetEncryptedMessage(token, socket, recipient, unidentifiedAccess, deviceId, plaintext));
                    }
                }
            }

            return new OutgoingPushMessageList(recipient.E164number, (ulong)timestamp, messages, online);
        }

        private async Task<OutgoingPushMessage> GetEncryptedMessage(CancellationToken token,
            PushServiceSocket socket,
            SignalServiceAddress recipient,
            UnidentifiedAccess? unidentifiedAccess,
            uint deviceId,
            byte[] plaintext)
        {
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipient.E164number, deviceId);
            SignalServiceCipher cipher = new SignalServiceCipher(LocalAddress, Store, null);

            if (!Store.ContainsSession(signalProtocolAddress))
            {
                try
                {
                    List<PreKeyBundle> preKeys = await socket.GetPreKeys(recipient, unidentifiedAccess, deviceId, token);

                    foreach (PreKeyBundle preKey in preKeys)
                    {
                        if (CredentialsProvider.User.Equals(recipient.E164number) && CredentialsProvider.DeviceId == preKey.getDeviceId())
                        {
                            continue;
                        }
                        try
                        {
                            SignalProtocolAddress preKeyAddress = new SignalProtocolAddress(recipient.E164number, preKey.getDeviceId());
                            SessionBuilder sessionBuilder = new SessionBuilder(Store, preKeyAddress);
                            sessionBuilder.process(preKey);
                        }
                        catch (libsignal.exceptions.UntrustedIdentityException)
                        {
                            throw new UntrustedIdentityException("Untrusted identity key!", recipient.E164number, preKey.getIdentityKey());
                        }
                    }

                    if (EventListener != null)
                    {
                        EventListener.OnSecurityEvent(recipient);
                    }
                }
                catch (InvalidKeyException e)
                {
                    throw new Exception(e.Message);
                }
            }

            try
            {
                return cipher.Encrypt(signalProtocolAddress, unidentifiedAccess, plaintext);
            }
            catch (libsignal.exceptions.UntrustedIdentityException e)
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
                    Store.DeleteSession(new SignalProtocolAddress(recipient.E164number, extraDeviceId));
                }

                foreach (uint missingDeviceId in mismatchedDevices.MissingDevices)
                {
                    PreKeyBundle preKey = await socket.GetPreKey(token, recipient, missingDeviceId);

                    try
                    {
                        SessionBuilder sessionBuilder = new SessionBuilder(Store, new SignalProtocolAddress(recipient.E164number, missingDeviceId));
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
                Store.DeleteSession(new SignalProtocolAddress(recipient.E164number, staleDeviceId));
            }
        }

        private UnidentifiedAccess? GetTargetUnidentifiedAccess(UnidentifiedAccessPair? unidentifiedAccess)
        {
            if (unidentifiedAccess != null)
            {
                return unidentifiedAccess.TargetUnidentifiedAccess;
            }

            return null;
        }

        private List<UnidentifiedAccess?> GetTargetUnidentifiedAccess(List<UnidentifiedAccessPair?> unidentifiedAccess)
        {
            List<UnidentifiedAccess?> results = new List<UnidentifiedAccess?>();
            foreach (UnidentifiedAccessPair? item in unidentifiedAccess)
            {
                if (item != null) results.Add(item.TargetUnidentifiedAccess);
                else results.Add(null);
            }
            return results;
        }

        public interface IEventListener
        {
            void OnSecurityEvent(SignalServiceAddress address);
        }
    }
}
