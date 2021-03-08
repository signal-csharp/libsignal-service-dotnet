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

        private readonly PushServiceSocket socket;
        private readonly SignalProtocolStore store;
        private readonly SignalServiceAddress localAddress;
        private readonly IEventListener? eventListener;
        private readonly ICredentialsProvider credentialsProvider;

        private SignalServiceMessagePipe? pipe;
        private SignalServiceMessagePipe? unidentifiedPipe;
        private bool isMultiDevice;
        private bool attachmentsV3;

        /// <summary>
        /// Construct a SignalServiceMessageSender
        /// </summary>
        /// <param name="urls">The URL of the Signal Service.</param>
        /// <param name="uuid">The Signal Service UUID.</param>
        /// <param name="e164">The Signal Service phone number.</param>
        /// <param name="password">The Signal Service user password</param>
        /// <param name="deviceId">The Signal Service device id</param>
        /// <param name="store">The SignalProtocolStore.</param>
        /// <param name="userAgent"></param>
        /// <param name="httpClient">HttpClient</param>
        /// <param name="isMultiDevice"></param>
        /// <param name="pipe">An optional SignalServiceMessagePipe</param>
        /// <param name="unidentifiedPipe"></param>
        /// <param name="eventListener">An optional event listener, which fires whenever sessions are
        /// setup or torn down for a recipient.</param>
        public SignalServiceMessageSender(SignalServiceConfiguration urls,
                                       Guid? uuid, string? e164, string password, int deviceId,
                                       SignalProtocolStore store,
                                       string userAgent,
                                       HttpClient httpClient,
                                       bool isMultiDevice,
                                       bool attachmentsV3,
                                       SignalServiceMessagePipe? pipe,
                                       SignalServiceMessagePipe? unidentifiedPipe,
                                       IEventListener? eventListener) :
            this(urls, new StaticCredentialsProvider(uuid, e164, password, deviceId), store, userAgent, httpClient, isMultiDevice, attachmentsV3, pipe, unidentifiedPipe, eventListener)
        {
        }

        public SignalServiceMessageSender(SignalServiceConfiguration urls,
            ICredentialsProvider credentialsProvider,
            SignalProtocolStore store,
            string userAgent,
            HttpClient httpClient,
            bool isMultiDevice,
            bool attachmentsV3,
            SignalServiceMessagePipe? pipe,
            SignalServiceMessagePipe? unidentifiedPipe,
            IEventListener? eventListener)
        {
            this.credentialsProvider = credentialsProvider;
            socket = new PushServiceSocket(urls, credentialsProvider, userAgent, httpClient);
            this.store = store;
            localAddress = new SignalServiceAddress(credentialsProvider.Uuid, credentialsProvider.E164);
            this.pipe = pipe;
            this.unidentifiedPipe = unidentifiedPipe;
            this.isMultiDevice = isMultiDevice;
            this.attachmentsV3 = attachmentsV3;
            this.eventListener = eventListener;
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

            if ((result.Success != null && result.Success.NeedsSync) || (unidentifiedAccess != null && isMultiDevice))
            {
                byte[] syncMessage = CreateMultiDeviceSentTranscriptContent(content, recipient, (ulong)timestamp, new List<SendMessageResult>() { result }, false);
                await SendMessageAsync(localAddress, unidentifiedAccess?.SelfUnidentifiedAccess, timestamp, syncMessage, false, token);
            }

            if (message.EndSession)
            {
                if (recipient.Uuid.HasValue)
                {
                    store.DeleteAllSessions(recipient.Uuid.Value.ToString());
                }
                if (recipient.GetNumber() != null)
                {
                    store.DeleteAllSessions(recipient.GetNumber());
                }

                if (eventListener != null)
                {
                    eventListener.OnSecurityEvent(recipient);
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
            bool isRecipientUpdate,
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
            if (needsSyncInResults || isMultiDevice)
            {
                byte[] syncMessage = CreateMultiDeviceSentTranscriptContent(content, null, (ulong) timestamp, results, isRecipientUpdate);
                await SendMessageAsync(localAddress, null, timestamp, syncMessage, false, token);
            }
            return results;
        }

        public void Update(SignalServiceMessagePipe pipe, SignalServiceMessagePipe unidentifiedPipe, bool isMultiDevice, bool attachmentsV3)
        {
            this.pipe = pipe;
            this.unidentifiedPipe = unidentifiedPipe;
            this.isMultiDevice = isMultiDevice;
            this.attachmentsV3 = attachmentsV3;
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
            Stream dataStream = new PaddingInputStream(attachment.InputStream, attachment.Length);
            long ciphertextLength = AttachmentCipherOutputStream.GetCiphertextLength(paddedLength);
            PushAttachmentData attachmentData = new PushAttachmentData(attachment.ContentType,
                                                                       dataStream,
                                                                       ciphertextLength,
                                                                       new AttachmentCipherOutputStreamFactory(attachmentKey),
                                                                       attachment.Listener);

            if (attachmentsV3)
            {
                return await UploadAttachmentV3Async(attachment, attachmentKey, attachmentData, token);
            }
            else
            {
                return await UploadAttachmentV2Async(attachment, attachmentKey, attachmentData, token);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="attachment"></param>
        /// <param name="attachmentKey"></param>
        /// <param name="attachmentData"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        /// <exception cref="PushNetworkException"></exception>
        public async Task<SignalServiceAttachmentPointer> UploadAttachmentV2Async(SignalServiceAttachmentStream attachment, byte[] attachmentKey, PushAttachmentData attachmentData,
            CancellationToken? token = null)
        {
            AttachmentV2UploadAttributes? v2UploadAttributes = null;
            SignalServiceMessagePipe? localPipe = pipe;

            if (localPipe != null)
            {
                Logger.LogDebug("Using pipe to retrieve attachment upload attributes...");
                try
                {
                    v2UploadAttributes = await localPipe.GetAttachmentV2UploadAttributesAsync();
                }
                catch (IOException)
                {
                    Logger.LogWarning("Failed to retrieve attachment upload attributes using pipe. Falling back...");
                }
            }

            if (v2UploadAttributes == null)
            {
                Logger.LogDebug("Not using pipe to retrieve attachment upload attributes...");
                v2UploadAttributes = await socket.GetAttachmentV2UploadAttributesAsync(token);
            }

            (long, byte[]) attachmentIdAndDigest = await socket.UploadAttachmentAsync(attachmentData, v2UploadAttributes, token);

            return new SignalServiceAttachmentPointer(0,
                new SignalServiceAttachmentRemoteId(attachmentIdAndDigest.Item1),
                attachment.ContentType,
                attachmentKey,
                (uint)Util.ToIntExact(attachment.Length),
                attachment.Preview,
                attachment.Width, attachment.Height,
                attachmentIdAndDigest.Item2,
                attachment.FileName,
                attachment.VoiceNote,
                attachment.Caption,
                attachment.BlurHash,
                attachment.UploadTimestamp);
        }


        public async Task<SignalServiceAttachmentPointer> UploadAttachmentV3Async(SignalServiceAttachmentStream attachment, byte[] attachmentKey, PushAttachmentData attachmentData,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            AttachmentV3UploadAttributes? v3UploadAttributes = null;
            SignalServiceMessagePipe? localPipe = pipe;

            if (localPipe != null)
            {
                Logger.LogDebug("Using pipe to retrieve attachment upload attributes...");
                try
                {
                    v3UploadAttributes = await localPipe.GetAttachmentV3UploadAttributesAsync();
                }
                catch (IOException)
                {
                    Logger.LogWarning("Failed to retrieve attachment upload attributes using pipe. Falling back...");
                }
            }

            if (v3UploadAttributes == null)
            {
                Logger.LogDebug("Not using pipe to retrieve attachment upload attributes...");
                v3UploadAttributes = await socket.GetAttachmentV3UploadAttributesAsync(token);
            }

            byte[] digest = await socket.UploadAttachmentAsync(attachmentData, v3UploadAttributes, token);
            return new SignalServiceAttachmentPointer(v3UploadAttributes.Cdn,
                new SignalServiceAttachmentRemoteId(v3UploadAttributes.Key!),
                attachment.ContentType,
                attachmentKey,
                (uint)Util.ToIntExact(attachment.Length),
                attachment.Preview,
                attachment.Width,
                attachment.Height,
                digest,
                attachment.FileName,
                attachment.VoiceNote,
                attachment.Caption,
                attachment.BlurHash,
                attachment.UploadTimestamp);
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
            else if (message.ViewOnceOpen != null)
            {
                content = CreateMultiDeviceViewOnceOpenContent(message.ViewOnceOpen);
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
            else if (message.StickerPackOperations != null)
            {
                content = CreateMultiDeviceStickerPackOperationContent(message.StickerPackOperations);
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

            long timestamp = message.Sent != null ? message.Sent.Timestamp :
                Util.CurrentTimeMillis();

            await SendMessageAsync(localAddress, unidenfifiedAccess?.SelfUnidentifiedAccess, timestamp, content, false, token);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="soTimeoutMillis"></param>
        public void SetSoTimeoutMillis(long soTimeoutMillis)
        {
            socket.SetSoTimeoutMillis(soTimeoutMillis);
        }

        /// <summary>
        /// 
        /// </summary>
        public void CancelInFlightRequests()
        {
            socket.CancelInFlightRequests();
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

            SendMessageResult result = await SendMessageAsync(message.Destination, unidentifiedAccessPair?.TargetUnidentifiedAccess, message.Timestamp, content, false, token);

            if (result.Success!.NeedsSync)
            {
                byte[] syncMessage = CreateMultiDeviceVerifiedContent(message, nullMessage.ToByteArray());
                await SendMessageAsync(localAddress, unidentifiedAccessPair?.SelfUnidentifiedAccess, message.Timestamp, syncMessage, false, token);
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

                foreach (AttachmentPointer pointer in pointers)
                {
                    if (pointer.AttachmentIdentifierCase == AttachmentPointer.AttachmentIdentifierOneofCase.CdnKey || pointer.CdnNumber != 0)
                    {
                        dataMessage.RequiredProtocolVersion = Math.Max((int)DataMessage.Types.ProtocolVersion.CdnSelectorAttachments, dataMessage.RequiredProtocolVersion);
                        break;
                    }
                }
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
                var quoteBuilder = new DataMessage.Types.Quote()
                {
                    Id = (ulong)message.Quote.Id,
                    Text = message.Quote.Text
                };

                if (message.Quote.Author.Uuid.HasValue)
                {
                    quoteBuilder.AuthorUuid = message.Quote.Author.Uuid.Value.ToString();
                }

                if (message.Quote.Author.GetNumber() != null)
                {
                    quoteBuilder.AuthorE164 = message.Quote.Author.GetNumber();
                }

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
                    quoteBuilder.Attachments.Add(protoAttachment);
                }
                dataMessage.Quote = quoteBuilder;
            }

            if (message.SharedContacts != null)
                dataMessage.Contact.AddRange(await CreateSharedContactContentAsync(message.SharedContacts, token));

            if (message.Previews != null)
            {
                foreach (SignalServicePreview preview in message.Previews)
                {
                    Preview previewBuilder = new Preview();
                    previewBuilder.Title = preview.Title;
                    previewBuilder.Url = preview.Url;

                    if (preview.Image != null)
                    {
                        if (preview.Image.IsStream())
                        {
                            previewBuilder.Image = await CreateAttachmentPointerAsync(preview.Image.AsStream(), token);
                        }
                        else
                        {
                            previewBuilder.Image = CreateAttachmentPointer(preview.Image.AsPointer());
                        }
                    }

                    dataMessage.Preview.Add(previewBuilder);
                }
            }

            if (message.Sticker != null)
            {
                Sticker stickerBuilder = new Sticker();

                stickerBuilder.PackId = ByteString.CopyFrom(message.Sticker.PackId);
                stickerBuilder.PackKey = ByteString.CopyFrom(message.Sticker.PackKey);
                stickerBuilder.StickerId = (uint)message.Sticker.StickerId;

                if (message.Sticker.Attachment.IsStream())
                {
                    stickerBuilder.Data = await CreateAttachmentPointerAsync(message.Sticker.Attachment.AsStream(), token);
                }
                else
                {
                    stickerBuilder.Data = CreateAttachmentPointer(message.Sticker.Attachment.AsPointer());
                }

                dataMessage.Sticker = stickerBuilder;
            }

            if (message.ViewOnce)
            {
                dataMessage.IsViewOnce = message.ViewOnce;
                dataMessage.RequiredProtocolVersion = Math.Max((int)DataMessage.Types.ProtocolVersion.ViewOnceVideo, dataMessage.RequiredProtocolVersion);
            }

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
            if (token == null)
            {
                token = CancellationToken.None;
            }

            SignalServiceAddress? address = transcript.Destination;
            SendMessageResult result = SendMessageResult.NewSuccess(address!, unidentifiedAccess != null, true);

            return CreateMultiDeviceSentTranscriptContent(await CreateMessageContentAsync(transcript.Message, token),
                address,
                (ulong)transcript.Timestamp,
                new List<SendMessageResult>() { result },
                false);
        }

        private byte[] CreateMultiDeviceSentTranscriptContent(byte[] content, SignalServiceAddress? recipient,
            ulong timestamp, List<SendMessageResult> sendMessageResults,
            bool isRecipientUpdate)
        {
            try
            {
                Content container = new Content { };
                SyncMessage syncMessage = CreateSyncMessage();
                SyncMessage.Types.Sent sentMessage = new SyncMessage.Types.Sent { };
                DataMessage dataMessage = Content.Parser.ParseFrom(content).DataMessage;

                sentMessage.Timestamp = timestamp;
                sentMessage.Message = dataMessage;

                foreach (var result in sendMessageResults)
                {
                    if (result.Success != null)
                    {
                        SyncMessage.Types.Sent.Types.UnidentifiedDeliveryStatus builder = new Sent.Types.UnidentifiedDeliveryStatus();

                        if (result.Address.Uuid.HasValue)
                        {
                            builder.DestinationUuid = result.Address.Uuid.Value.ToString();
                        }

                        if (result.Address.GetNumber() != null)
                        {
                            builder.DestinationE164 = result.Address.GetNumber();
                        }

                        builder.Unidentified = result.Success.Unidentified;

                        sentMessage.UnidentifiedStatus.Add(builder);
                    }
                }

                if (recipient != null)
                {
                    if (recipient.Uuid.HasValue) sentMessage.DestinationUuid = recipient.Uuid.Value.ToString();
                    if (recipient.GetNumber() != null) sentMessage.DestinationE164 = recipient.GetNumber();
                }

                if (dataMessage.ExpireTimer > 0)
                {
                    sentMessage.ExpirationStartTimestamp = (ulong)Util.CurrentTimeMillis();
                }

                if (dataMessage.IsViewOnce)
                {
                    dataMessage.Attachments.Clear();
                    sentMessage.Message = dataMessage;
                }

                sentMessage.IsRecipientUpdate = isRecipientUpdate;

                syncMessage.Sent = sentMessage;
                container.SyncMessage = syncMessage;
                return container.ToByteArray();
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
                SyncMessage.Types.Read readBuilder = new Read()
                {
                    Timestamp = (ulong)readMessage.Timestamp
                };

                if (readMessage.Sender.Uuid.HasValue)
                {
                    readBuilder.SenderUuid = readMessage.Sender.Uuid.Value.ToString();
                }

                if (readMessage.Sender.GetNumber() != null)
                {
                    readBuilder.SenderE164 = readMessage.Sender.GetNumber();
                }
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

        private byte[] CreateMultiDeviceViewOnceOpenContent(ViewOnceOpenMessage readMessage)
        {
            Content container = new Content();
            SyncMessage builder = CreateSyncMessage();
            ViewOnceOpen viewOnceBuilder = new ViewOnceOpen()
            {
                Timestamp = (ulong)readMessage.Timestamp
            };

            if (readMessage.Sender.Uuid.HasValue)
            {
                viewOnceBuilder.SenderUuid = readMessage.Sender.Uuid.Value.ToString();
            }

            if (readMessage.Sender.GetNumber() != null)
            {
                viewOnceBuilder.SenderE164 = readMessage.Sender.GetNumber();
            }

            builder.ViewOnceOpen = viewOnceBuilder;

            container.SyncMessage = builder;
            return container.ToByteArray();
        }

        private byte[] CreateMultiDeviceBlockedContent(BlockedListMessage blocked)
        {
            Content content = new Content { };
            SyncMessage syncMessage = new SyncMessage { };
            Blocked blockedMessage = new Blocked { };

            foreach (SignalServiceAddress address in blocked.Addresses)
            {
                if (address.Uuid.HasValue)
                {
                    blockedMessage.Uuids.Add(address.Uuid.Value.ToString());
                }
                if (address.GetNumber() != null)
                {
                    blockedMessage.Numbers.Add(address.GetNumber());
                }
            }

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

            if (configuration.LinkPreviews.HasValue)
            {
                configurationMessage.LinkPreviews = configuration.LinkPreviews.Value;
            }

            syncMessage.Configuration = configurationMessage;
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] CreateMultiDeviceStickerPackOperationContent(List<StickerPackOperationMessage> stickerPackOperations)
        {
            Content content = new Content();
            SyncMessage syncMessage = CreateSyncMessage();

            foreach (StickerPackOperationMessage stickerPackOperation in stickerPackOperations)
            {
                StickerPackOperation builder = new StickerPackOperation();

                if (stickerPackOperation.PackId != null)
                {
                    builder.PackId = ByteString.CopyFrom(stickerPackOperation.PackId);
                }

                if (stickerPackOperation.PackKey != null)
                {
                    builder.PackKey = ByteString.CopyFrom(stickerPackOperation.PackKey);
                }

                if (stickerPackOperation.Type != null)
                {
                    switch (stickerPackOperation.Type)
                    {
                        case StickerPackOperationMessage.OperationType.Install: builder.Type = StickerPackOperation.Types.Type.Install; break;
                        case StickerPackOperationMessage.OperationType.Remove: builder.Type = StickerPackOperation.Types.Type.Remove; break;
                    }
                }

                syncMessage.StickerPackOperation.Add(builder);
            }

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
                IdentityKey = ByteString.CopyFrom(verifiedMessage.IdentityKey.serialize())
            };

            if (verifiedMessage.Destination.Uuid.HasValue)
            {
                verifiedMessageBuilder.DestinationUuid = verifiedMessage.Destination.Uuid.Value.ToString();
            }

            if (verifiedMessage.Destination.GetNumber() != null)
            {
                verifiedMessageBuilder.DestinationE164 = verifiedMessage.Destination.GetNumber();
            }

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
                    throw new ArgumentException("Unknown: " + verifiedMessage.Verified);
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

            GroupContext builder = new GroupContext();
            builder.Id = ByteString.CopyFrom(group.GroupId);

            if (group.Type != SignalServiceGroup.GroupType.DELIVER)
            {
                if (group.Type == SignalServiceGroup.GroupType.UPDATE) builder.Type = GroupContext.Types.Type.Update;
                else if (group.Type == SignalServiceGroup.GroupType.QUIT) builder.Type = GroupContext.Types.Type.Quit;
                else if (group.Type == SignalServiceGroup.GroupType.REQUEST_INFO) builder.Type = GroupContext.Types.Type.RequestInfo;
                else throw new Exception("Unknown type: " + group.Type);

                if (group.Name != null)
                {
                    builder.Name = group.Name;
                }

                if (group.Members != null)
                {
                    foreach (SignalServiceAddress address in group.Members)
                    {
                        if (address.GetNumber() != null)
                        {
                            builder.MembersE164.Add(address.GetNumber());
                        }

                        GroupContext.Types.Member memberBuilder = new GroupContext.Types.Member();

                        if (address.Uuid.HasValue)
                        {
                            memberBuilder.Uuid = address.Uuid.Value.ToString();
                        }

                        if (address.GetNumber() != null)
                        {
                            memberBuilder.E164 = address.GetNumber();
                        }

                        builder.Members.Add(memberBuilder);
                    }
                }

                if (group.Avatar != null)
                {
                    if (group.Avatar.IsStream())
                    {
                        builder.Avatar = await CreateAttachmentPointerAsync(group.Avatar.AsStream(), token);
                    }
                    else
                    {
                        builder.Avatar = CreateAttachmentPointer(group.Avatar.AsPointer());
                    }
                }
            }
            else
            {
                builder.Type = GroupContext.Types.Type.Deliver;
            }

            return builder;
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
                    AttachmentPointer pointer = contact.Avatar.Attachment.IsStream() ?
                        await CreateAttachmentPointerAsync(contact.Avatar.Attachment.AsStream(), token) :
                        CreateAttachmentPointer(contact.Avatar.Attachment.AsPointer());

                    contactBuilder.Avatar = new Contact.Types.Avatar()
                    {
                        Avatar_ = pointer,
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
                    OutgoingPushMessageList messages = await GetEncryptedMessagesAsync(socket, recipient, unidentifiedAccess, timestamp, content, online, token);
                    var pipe = this.pipe;
                    var unidentifiedPipe = this.unidentifiedPipe;
                    if (this.pipe != null && unidentifiedAccess == null)
                    {
                        try
                        {
                            Logger.LogTrace("Transmitting over pipe...");
                            var response = await this.pipe.Send(messages, null);
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
                    SendMessageResponse resp = await socket.SendMessageAsync(messages, unidentifiedAccess, token);
                    return SendMessageResult.NewSuccess(recipient, unidentifiedAccess != null, resp.NeedsSync);
                }
                catch (MismatchedDevicesException mde)
                {
                    await HandleMismatchedDevicesAsync(socket, recipient, mde.MismatchedDevices, token);
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
                    pointers.Add(CreateAttachmentPointer(attachment.AsPointer()));
                }
            }

            return pointers;
        }

        private AttachmentPointer CreateAttachmentPointer(SignalServiceAttachmentPointer attachment)
        {
            var builder = new AttachmentPointer
            {
                CdnNumber = (uint)attachment.CdnNumber,
                ContentType = attachment.ContentType,
                Key = ByteString.CopyFrom(attachment.Key),
                Digest = ByteString.CopyFrom(attachment.Digest)
            };

            if (attachment.Size.HasValue)
            {
                builder.Size = attachment.Size.Value;
            }

            if (attachment.RemoteId.V2.HasValue)
            {
                builder.CdnId = (ulong)attachment.RemoteId.V2.Value;
            }

            if (attachment.RemoteId.V3 != null)
            {
                builder.CdnKey = attachment.RemoteId.V3;
            }

            if (attachment.FileName != null)
            {
                builder.FileName = attachment.FileName;
            }

            if (attachment.Preview != null)
            {
                builder.Thumbnail = ByteString.CopyFrom(attachment.Preview);
            }

            if (attachment.Width > 0)
            {
                builder.Width = (uint)attachment.Width;
            }

            if (attachment.Height > 0)
            {
                builder.Height = (uint)attachment.Height;
            }

            if (attachment.VoiceNote)
            {
                builder.Flags = (uint)AttachmentPointer.Types.Flags.VoiceMessage;
            }

            if (attachment.Caption != null)
            {
                builder.Caption = attachment.Caption;
            }

            if (attachment.BlurHash != null)
            {
                builder.BlurHash = attachment.BlurHash;
            }

            return builder;
        }

        private async Task<AttachmentPointer> CreateAttachmentPointerAsync(SignalServiceAttachmentStream attachment,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            return CreateAttachmentPointer(await UploadAttachmentAsync(attachment, token));
        }

        private async Task<OutgoingPushMessageList> GetEncryptedMessagesAsync(PushServiceSocket socket,
            SignalServiceAddress recipient,
            UnidentifiedAccess? unidentifiedAccess,
            long timestamp,
            byte[] plaintext,
            bool online,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            List<OutgoingPushMessage> messages = new List<OutgoingPushMessage>();

            bool myself = recipient.Equals(localAddress);
            if (!myself || credentialsProvider.DeviceId != SignalServiceAddress.DEFAULT_DEVICE_ID ||
                !recipient.Matches(localAddress) || unidentifiedAccess != null)
            {
                messages.Add(await GetEncryptedMessageAsync(socket, recipient, unidentifiedAccess, SignalServiceAddress.DEFAULT_DEVICE_ID, plaintext, token));
            }

            foreach (uint deviceId in store.GetSubDeviceSessions(recipient.GetIdentifier()))
            {
                if (!myself || deviceId != credentialsProvider.DeviceId)
                {
                    if (store.ContainsSession(new SignalProtocolAddress(recipient.GetIdentifier(), deviceId)))
                    {
                        messages.Add(await GetEncryptedMessageAsync(socket, recipient, unidentifiedAccess, deviceId, plaintext, token));
                    }
                }
            }

            return new OutgoingPushMessageList(recipient.GetIdentifier()!, (ulong)timestamp, messages, online);
        }

        private async Task<OutgoingPushMessage> GetEncryptedMessageAsync(PushServiceSocket socket,
            SignalServiceAddress recipient,
            UnidentifiedAccess? unidentifiedAccess,
            uint deviceId,
            byte[] plaintext,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipient.GetIdentifier(), deviceId);
            SignalServiceCipher cipher = new SignalServiceCipher(localAddress, store, null);

            if (!store.ContainsSession(signalProtocolAddress))
            {
                try
                {
                    List<PreKeyBundle> preKeys = await socket.GetPreKeysAsync(recipient, unidentifiedAccess, deviceId, token);

                    foreach (PreKeyBundle preKey in preKeys)
                    {
                        if ((credentialsProvider.Uuid == recipient.Uuid || credentialsProvider.E164 == recipient.E164) &&
                            credentialsProvider.DeviceId == preKey.getDeviceId())
                        {
                            continue;
                        }
                        try
                        {
                            SignalProtocolAddress preKeyAddress = new SignalProtocolAddress(recipient.GetIdentifier(), preKey.getDeviceId());
                            SessionBuilder sessionBuilder = new SessionBuilder(store, preKeyAddress);
                            sessionBuilder.process(preKey);
                        }
                        catch (libsignal.exceptions.UntrustedIdentityException)
                        {
                            throw new UntrustedIdentityException("Untrusted identity key!", recipient.GetIdentifier(), preKey.getIdentityKey());
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
                return cipher.Encrypt(signalProtocolAddress, unidentifiedAccess, plaintext);
            }
            catch (libsignal.exceptions.UntrustedIdentityException e)
            {
                throw new UntrustedIdentityException("Untrusted on send", e.getName(), e.getUntrustedIdentity());
            }
        }

        private async Task HandleMismatchedDevicesAsync(PushServiceSocket socket, SignalServiceAddress recipient, MismatchedDevices mismatchedDevices, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            try
            {
                foreach (uint extraDeviceId in mismatchedDevices.ExtraDevices)
                {
                    if (recipient.Uuid.HasValue)
                    {
                        store.DeleteSession(new SignalProtocolAddress(recipient.Uuid.Value.ToString(), extraDeviceId));
                    }

                    if (recipient.GetNumber() != null)
                    {
                        store.DeleteSession(new SignalProtocolAddress(recipient.GetNumber(), extraDeviceId));
                    }
                }

                foreach (uint missingDeviceId in mismatchedDevices.MissingDevices)
                {
                    PreKeyBundle preKey = await socket.GetPreKeyAsync(recipient, missingDeviceId, token);

                    try
                    {
                        SessionBuilder sessionBuilder = new SessionBuilder(store, new SignalProtocolAddress(recipient.GetIdentifier(), missingDeviceId));
                        sessionBuilder.process(preKey);
                    }
                    catch (libsignal.exceptions.UntrustedIdentityException)
                    {
                        throw new UntrustedIdentityException("Untrusted identity key!", recipient.GetIdentifier(), preKey.getIdentityKey());
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
                if (recipient.Uuid.HasValue)
                {
                    store.DeleteSession(new SignalProtocolAddress(recipient.Uuid.Value.ToString(), staleDeviceId));
                }
                if (recipient.GetNumber() != null)
                {
                    store.DeleteSession(new SignalProtocolAddress(recipient.GetNumber(), staleDeviceId));
                }
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
