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
            await SendMessage(token, recipient, unidentifiedAccess?.TargetUnidentifiedAccess, Util.CurrentTimeMillis(), content);
        }

        /// <summary>
        /// Send a message to a single recipient.
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="recipient">The message's destination.</param>
        /// <param name="unidentifiedAccess"></param>
        /// <param name="message">The message.</param>
        public async Task<SendMessageResult> SendMessage(CancellationToken token, SignalServiceAddress recipient,
            UnidentifiedAccessPair? unidentifiedAccess, SignalServiceDataMessage message)
        {
            byte[] content = await CreateMessageContent(token, message);
            long timestamp = message.Timestamp;
            SendMessageResult result = await SendMessage(token, recipient, unidentifiedAccess?.TargetUnidentifiedAccess, timestamp, content);

            if ((result.Success != null && result.Success.NeedsSync) || (unidentifiedAccess != null && IsMultiDevice))
            {
                byte[] syncMessage = CreateMultiDeviceSentTranscriptContent(content, recipient, (ulong)timestamp, new List<SendMessageResult>() { result });
                await SendMessage(token, LocalAddress, unidentifiedAccess?.SelfUnidentifiedAccess, timestamp, syncMessage);
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
        public async Task<List<SendMessageResult>> SendMessage(CancellationToken token, List<SignalServiceAddress> recipients,
            List<UnidentifiedAccessPair?> unidentifiedAccess, SignalServiceDataMessage message)
        {
            byte[] content = await CreateMessageContent(token, message);
            long timestamp = message.Timestamp;
            List<SendMessageResult> results = await SendMessage(token, recipients, GetTargetUnidentifiedAccess(unidentifiedAccess), timestamp, content);
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
                await SendMessage(token, LocalAddress, GetSelfUnidentifiedAccess(unidentifiedAccess), timestamp, syncMessage);
            }
            return results;
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="token"></param>
        /// <param name="message"></param>
        /// <param name="unidenfifiedAccess"></param>
        public async Task SendMessage(CancellationToken token, SignalServiceSyncMessage message, UnidentifiedAccessPair? unidenfifiedAccess)
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
                await SendMessage(token, message.Verified, unidenfifiedAccess);
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

            await SendMessage(token, LocalAddress, unidenfifiedAccess?.SelfUnidentifiedAccess, Util.CurrentTimeMillis(), content);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="soTimeoutMillis"></param>
        public void SetSoTimeoutMillis(long soTimeoutMillis)
        {
            Socket.SetSoTimeoutMillis(soTimeoutMillis);
        }

        /// <summary>
        /// TODO
        /// </summary>
        public void CancelInFlightRequests()
        {
            Socket.CancelInFlightRequests();
        }

        private async Task SendMessage(CancellationToken token, VerifiedMessage message, UnidentifiedAccessPair? unidentifiedAccessPair)
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

            SendMessageResult result = await SendMessage(token, new SignalServiceAddress(message.Destination), unidentifiedAccessPair?.TargetUnidentifiedAccess, message.Timestamp, content);

            if (result.Success.NeedsSync)
            {
                byte[] syncMessage = CreateMultiDeviceVerifiedContent(message, nullMessage.ToByteArray());
                await SendMessage(token, LocalAddress, unidentifiedAccessPair?.SelfUnidentifiedAccess, message.Timestamp, syncMessage);
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
                        protoAttachment.Thumbnail = await CreateAttachmentPointer(token, attachment.Thumbnail.AsStream());
                    }
                    quote.Attachments.Add(protoAttachment);
                }
                dataMessage.Quote = quote;
            }

            if (message.SharedContacts != null)
                dataMessage.Contact.AddRange(CreateSharedContactContent(message.SharedContacts));

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
                if (group.Members != null) groupContext.Members.AddRange(group.Members);

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

        private async Task<List<SendMessageResult>> SendMessage(CancellationToken token, List<SignalServiceAddress> recipients,
            List<UnidentifiedAccess?> unidentifiedAccess, long timestamp, byte[] content)
        {
            List<SendMessageResult> results = new List<SendMessageResult>();
            for (int i = 0; i < recipients.Count; i++)
            {
                var recipient = recipients[i];
                try
                {
                    var result = await SendMessage(token, recipient, unidentifiedAccess[i], timestamp, content);
                    results.Add(result);
                }
                catch (UntrustedIdentityException e)
                {
                    results.Add(SendMessageResult.NewIdentityFailure(recipient, e.IdentityKey));
                }
                catch (UnregisteredUserException e)
                {
                    results.Add(SendMessageResult.NewUnregisteredFailure(recipient));
                }
                catch (PushNetworkException e)
                {
                    results.Add(SendMessageResult.NewNetworkFailure(recipient));
                }
            }
            return results;
        }

        private List<Contact> CreateSharedContactContent(List<SharedContact> contacts)
        {
            List<Contact> results = new List<Contact>();

            foreach (var contact in contacts)
            {
                //TODO
                /*
                DataMessage.Contact.Name.Builder nameBuilder = DataMessage.Contact.Name.newBuilder();

                if (contact.getName().getFamily().isPresent()) nameBuilder.setFamilyName(contact.getName().getFamily().get());
                if (contact.getName().getGiven().isPresent()) nameBuilder.setGivenName(contact.getName().getGiven().get());
                if (contact.getName().getMiddle().isPresent()) nameBuilder.setMiddleName(contact.getName().getMiddle().get());
                if (contact.getName().getPrefix().isPresent()) nameBuilder.setPrefix(contact.getName().getPrefix().get());
                if (contact.getName().getSuffix().isPresent()) nameBuilder.setSuffix(contact.getName().getSuffix().get());
                if (contact.getName().getDisplay().isPresent()) nameBuilder.setDisplayName(contact.getName().getDisplay().get());

                DataMessage.Contact.Builder contactBuilder = DataMessage.Contact.newBuilder()
                                                                                .setName(nameBuilder);

                if (contact.getAddress().isPresent())
                {
                    for (SharedContact.PostalAddress address : contact.getAddress().get())
                    {
                        DataMessage.Contact.PostalAddress.Builder addressBuilder = DataMessage.Contact.PostalAddress.newBuilder();

                        switch (address.getType())
                        {
                            case HOME: addressBuilder.setType(DataMessage.Contact.PostalAddress.Type.HOME); break;
                            case WORK: addressBuilder.setType(DataMessage.Contact.PostalAddress.Type.WORK); break;
                            case CUSTOM: addressBuilder.setType(DataMessage.Contact.PostalAddress.Type.CUSTOM); break;
                            default: throw new AssertionError("Unknown type: " + address.getType());
                        }

                        if (address.getCity().isPresent()) addressBuilder.setCity(address.getCity().get());
                        if (address.getCountry().isPresent()) addressBuilder.setCountry(address.getCountry().get());
                        if (address.getLabel().isPresent()) addressBuilder.setLabel(address.getLabel().get());
                        if (address.getNeighborhood().isPresent()) addressBuilder.setNeighborhood(address.getNeighborhood().get());
                        if (address.getPobox().isPresent()) addressBuilder.setPobox(address.getPobox().get());
                        if (address.getPostcode().isPresent()) addressBuilder.setPostcode(address.getPostcode().get());
                        if (address.getRegion().isPresent()) addressBuilder.setRegion(address.getRegion().get());
                        if (address.getStreet().isPresent()) addressBuilder.setStreet(address.getStreet().get());

                        contactBuilder.addAddress(addressBuilder);
                    }
                }

                if (contact.getEmail().isPresent())
                {
                    for (SharedContact.Email email : contact.getEmail().get())
                    {
                        DataMessage.Contact.Email.Builder emailBuilder = DataMessage.Contact.Email.newBuilder()
                                                                                                  .setValue(email.getValue());

                        switch (email.getType())
                        {
                            case HOME: emailBuilder.setType(DataMessage.Contact.Email.Type.HOME); break;
                            case WORK: emailBuilder.setType(DataMessage.Contact.Email.Type.WORK); break;
                            case MOBILE: emailBuilder.setType(DataMessage.Contact.Email.Type.MOBILE); break;
                            case CUSTOM: emailBuilder.setType(DataMessage.Contact.Email.Type.CUSTOM); break;
                            default: throw new AssertionError("Unknown type: " + email.getType());
                        }

                        if (email.getLabel().isPresent()) emailBuilder.setLabel(email.getLabel().get());

                        contactBuilder.addEmail(emailBuilder);
                    }
                }

                if (contact.getPhone().isPresent())
                {
                    for (SharedContact.Phone phone : contact.getPhone().get())
                    {
                        DataMessage.Contact.Phone.Builder phoneBuilder = DataMessage.Contact.Phone.newBuilder()
                                                                                                  .setValue(phone.getValue());

                        switch (phone.getType())
                        {
                            case HOME: phoneBuilder.setType(DataMessage.Contact.Phone.Type.HOME); break;
                            case WORK: phoneBuilder.setType(DataMessage.Contact.Phone.Type.WORK); break;
                            case MOBILE: phoneBuilder.setType(DataMessage.Contact.Phone.Type.MOBILE); break;
                            case CUSTOM: phoneBuilder.setType(DataMessage.Contact.Phone.Type.CUSTOM); break;
                            default: throw new AssertionError("Unknown type: " + phone.getType());
                        }

                        if (phone.getLabel().isPresent()) phoneBuilder.setLabel(phone.getLabel().get());

                        contactBuilder.addNumber(phoneBuilder);
                    }
                }

                if (contact.getAvatar().isPresent())
                {
                    contactBuilder.setAvatar(DataMessage.Contact.Avatar.newBuilder()
                                                                       .setAvatar(createAttachmentPointer(contact.getAvatar().get().getAttachment().asStream()))
                                                                       .setIsProfile(contact.getAvatar().get().isProfile()));
                }

                if (contact.getOrganization().isPresent())
                {
                    contactBuilder.setOrganization(contact.getOrganization().get());
                }

                results.add(contactBuilder.build());
                */
            }
            return results;
        }

        private async Task<SendMessageResult> SendMessage(CancellationToken token,
            SignalServiceAddress recipient,
            UnidentifiedAccess? unidentifiedAccess,
            long timestamp,
            byte[] content)
        {
            for (int i = 0; i < 4; i++)
            {
                try
                {
                    OutgoingPushMessageList messages = await GetEncryptedMessages(token, Socket, recipient, unidentifiedAccess, timestamp, content);
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
                    await HandleMismatchedDevices(token, Socket, recipient, mde.MismatchedDevices);
                }
                catch (StaleDevicesException ste)
                {
                    HandleStaleDevices(recipient, ste.StaleDevices);
                }
            }
            Logger.LogError("Failed to resolve conflicts after 3 attempts!");
            throw new Exception("Failed to resolve conflicts after 3 attempts!");
        }

        private async Task<IList<AttachmentPointer>> CreateAttachmentPointers(CancellationToken token, List<SignalServiceAttachment>? attachments)
        {
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

            (ulong id, byte[] digest) = await Socket.SendAttachment(token, attachmentData);

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

        private async Task<OutgoingPushMessageList> GetEncryptedMessages(CancellationToken token,
            PushServiceSocket socket,
            SignalServiceAddress recipient,
            UnidentifiedAccess? unidentifiedAccess,
            long timestamp,
            byte[] plaintext)
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

            return new OutgoingPushMessageList(recipient.E164number, (ulong)timestamp, recipient.Relay, messages);
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

        private UnidentifiedAccess? GetSelfUnidentifiedAccess(List<UnidentifiedAccessPair?> unidentifiedAccess)
        {
            foreach (UnidentifiedAccessPair? item in unidentifiedAccess)
            {
                if (item != null && item.SelfUnidentifiedAccess != null)
                {
                    return item.SelfUnidentifiedAccess;
                }
            }
            return null;
        }


#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        public interface IEventListener
        {
            void OnSecurityEvent(SignalServiceAddress address);
        }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
