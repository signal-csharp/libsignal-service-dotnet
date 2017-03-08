﻿/** 
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
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using libsignal;
using libsignal.state;
using libsignalservice.crypto;
using libsignalservice.messages;
using libsignalservice.messages.multidevice;
using libsignalservice.push;
using libsignalservice.push.exceptions;
using libsignalservice.util;
using Strilanc.Value;
using Google.Protobuf;

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
        public SignalServiceMessageSender(SignalServiceUrl[] urls,
                                       string user, string password,
                                       SignalProtocolStore store,
                                       SignalServiceMessagePipe pipe,
                                       EventListener eventListener, string userAgent)
        {
            this.socket = new PushServiceSocket(urls, new StaticCredentialsProvider(user, password, null), userAgent);
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

        /// <summary>
        /// Send a message to a single recipient.
        /// </summary>
        /// <param name="recipient">The message's destination.</param>
        /// <param name="message">The message.</param>
        public void sendMessage(SignalServiceAddress recipient, SignalServiceDataMessage message)
        {
            byte[] content = createMessageContent(message);
            long timestamp = message.getTimestamp();
            bool silent = message.getGroupInfo().HasValue && message.getGroupInfo().ForceGetValue().getType() == SignalServiceGroup.Type.REQUEST_INFO;
            SendMessageResponse response = sendMessage(recipient, timestamp, content, true, silent);

            if(response != null && response.getNeedsSync())
            {
                byte[] syncMessage = createMultiDeviceSentTranscriptContent(content, new May<SignalServiceAddress>(recipient), (ulong)timestamp);
                sendMessage(localAddress, timestamp, syncMessage, false, false);
            }

            if(message.isEndSession())
            {
                store.DeleteAllSessions(recipient.getNumber());

                if(eventListener != null)
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
            long timestamp = message.getTimestamp();
            SendMessageResponse response = sendMessage(recipients, timestamp, content, true);

            try
            {
                if (response != null && response.getNeedsSync())
                {
                    byte[] syncMessage = createMultiDeviceSentTranscriptContent(content, May<SignalServiceAddress>.NoValue, (ulong)timestamp);
                    sendMessage(localAddress, timestamp, syncMessage, false, false);
                }
            }
            catch (UntrustedIdentityException e)
            {
                throw new EncapsulatedExceptions(e);
            }
        }

        public void sendMessage(SignalServiceSyncMessage message)
        {
            byte[] content;

            if (message.getContacts().HasValue)
            {
                content = createMultiDeviceContactsContent(message.getContacts().ForceGetValue().asStream());
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
            else
            {
                throw new Exception("Unsupported sync message!");
            }

            sendMessage(localAddress, Util.CurrentTimeMillis(), content, false, false);
        }

        private byte[] createMessageContent(SignalServiceDataMessage message)// throws IOException
        {
            DataMessage dataMessage = new DataMessage { };
            IList<AttachmentPointer> pointers = createAttachmentPointers(message.getAttachments());

            if (pointers.Count != 0)
            {
                dataMessage.Attachments.AddRange(pointers);
            }

            if (message.getBody().HasValue)
            {
                dataMessage.Body = message.getBody().ForceGetValue();
            }

            if (message.getGroupInfo().HasValue)
            {
                dataMessage.Group = createGroupContent(message.getGroupInfo().ForceGetValue());
            }

            if (message.isEndSession())
            {
                dataMessage.Flags = (uint)DataMessage.Types.Flags.EndSession;
            }

            if (message.isExpirationUpdate())
            {
                dataMessage.Flags = (uint)DataMessage.Types.Flags.ExpirationTimerUpdate;
            }

            if (message.getExpiresInSeconds() > 0)
            {
                dataMessage.ExpireTimer = (uint)message.getExpiresInSeconds();
            }

            return dataMessage.ToByteArray();
        }
        private byte[] createMultiDeviceContactsContent(SignalServiceAttachmentStream contacts)
        {
            Content content = new Content { };
            SyncMessage syncMessage = new SyncMessage { };
            syncMessage.Contacts = new SyncMessage.Types.Contacts
            {
                Blob = createAttachmentPointer(contacts)
            };
            content.SyncMessage = syncMessage;
            return content.ToByteArray();
        }

        private byte[] createMultiDeviceGroupsContent(SignalServiceAttachmentStream groups)
        {
            Content content = new Content { };
            SyncMessage syncMessage = new SyncMessage { };
            syncMessage.Groups = new SyncMessage.Types.Groups {
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
                SyncMessage syncMessage = new SyncMessage { };
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
            SyncMessage syncMessage = new SyncMessage { };

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

        private GroupContext createGroupContent(SignalServiceGroup group)
        {
            GroupContext groupContext = new GroupContext { };
            groupContext.Id = ByteString.CopyFrom(group.getGroupId());

            if (group.getType() != SignalServiceGroup.Type.DELIVER)
            {
                if (group.getType() == SignalServiceGroup.Type.UPDATE) groupContext.Type = GroupContext.Types.Type.Update;
                else if (group.getType() == SignalServiceGroup.Type.QUIT) groupContext.Type = GroupContext.Types.Type.Quit;
                else if (group.getType() == SignalServiceGroup.Type.REQUEST_INFO) groupContext.Type = GroupContext.Types.Type.RequestInfo;
                else throw new Exception("Unknown type: " + group.getType());

                if (group.getName().HasValue) groupContext.Name = group.getName().ForceGetValue();
                if (group.getMembers().HasValue) groupContext.Members.AddRange(group.getMembers().ForceGetValue());

                if (group.getAvatar().HasValue && group.getAvatar().ForceGetValue().isStream())
                {
                    AttachmentPointer pointer = createAttachmentPointer(group.getAvatar().ForceGetValue().asStream());
                    groupContext.Avatar = pointer;
                }
            }
            else
            {
                groupContext.Type = GroupContext.Types.Type.Deliver;
            }

            return groupContext;
        }

        private SendMessageResponse sendMessage(List<SignalServiceAddress> recipients, long timestamp, byte[] content, bool legacy)
        {
            IList<UntrustedIdentityException> untrustedIdentities = new List<UntrustedIdentityException>(); // was linkedlist
            IList<UnregisteredUserException> unregisteredUsers = new List<UnregisteredUserException>();
            IList<NetworkFailureException> networkExceptions = new List<NetworkFailureException>();

            SendMessageResponse response = null;

            foreach (SignalServiceAddress recipient in recipients)
            {
                try
                {
                    response = sendMessage(recipient, timestamp, content, legacy, false);
                }
                catch (UntrustedIdentityException e)
                {
                    Debug.WriteLine("untrusted identity: " + recipient, TAG);
                    untrustedIdentities.Add(e);
                }
                catch (UnregisteredUserException e)
                {
                    Debug.WriteLine("unregistered user: " + recipient, TAG);
                    unregisteredUsers.Add(e);
                }
                catch (PushNetworkException e)
                {
                    Debug.WriteLine("PushNetWorkException for:" + recipient, TAG);
                    networkExceptions.Add(new NetworkFailureException(recipient.getNumber(), e));
                }
            }

            if (!(untrustedIdentities.Count == 0) || !(unregisteredUsers.Count == 0) || !(networkExceptions.Count == 0))
            {
                throw new EncapsulatedExceptions(untrustedIdentities, unregisteredUsers, networkExceptions);
            }

            return response;
        }

        private SendMessageResponse sendMessage(SignalServiceAddress recipient, long timestamp, byte[] content, bool legacy, bool silent)
        {
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    OutgoingPushMessageList messages = getEncryptedMessages(socket, recipient, timestamp, content, legacy, silent);

                    if(pipe != null && false)
                    {
                        try
                        {
                            Debug.WriteLine("Transmitting over pipe...");
                            return pipe.send(messages);
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

        private IList<AttachmentPointer> createAttachmentPointers(May<List<SignalServiceAttachment>> attachments)
        {
            IList<AttachmentPointer> pointers = new List<AttachmentPointer>();

            if (!attachments.HasValue || attachments.ForceGetValue().Count == 0)
            {
                Debug.WriteLine("No attachments present...", TAG);
                return pointers;
            }

            foreach (SignalServiceAttachment attachment in attachments.ForceGetValue())
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

            ulong attachmentId = socket.sendAttachment(attachmentData);

            var attachmentPointer = new AttachmentPointer
            {
                ContentType = attachment.getContentType(),
                Id = attachmentId,
                Key = ByteString.CopyFrom(attachmentKey),
                Size = (uint)attachment.getLength()
            };
                                    

            if (attachment.getPreview().HasValue)
            {
                attachmentPointer.Thumbnail = ByteString.CopyFrom(attachment.getPreview().ForceGetValue());
            }

            return attachmentPointer;
        }


        private OutgoingPushMessageList getEncryptedMessages(PushServiceSocket socket,
                                                   SignalServiceAddress recipient,
                                                   long timestamp,
                                                   byte[] plaintext,
                                                   bool legacy,
                                                   bool silent)
        {
            List<OutgoingPushMessage> messages = new List<OutgoingPushMessage>();

            if (!recipient.Equals(localAddress))
            {
                messages.Add(getEncryptedMessage(socket, recipient, SignalServiceAddress.DEFAULT_DEVICE_ID, plaintext, legacy, silent));
            }

            foreach (uint deviceId in store.GetSubDeviceSessions(recipient.getNumber()))
            {
                messages.Add(getEncryptedMessage(socket, recipient, deviceId, plaintext, legacy, silent));
            }

            return new OutgoingPushMessageList(recipient.getNumber(), (ulong)timestamp, recipient.getRelay().HasValue ? recipient.getRelay().ForceGetValue() : null, messages);
        }

        private OutgoingPushMessage getEncryptedMessage(PushServiceSocket socket, SignalServiceAddress recipient, uint deviceId, byte[] plaintext, bool legacy, bool silent)
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

                    if(eventListener != null)
                    {
                        eventListener.onSecurityEvent(recipient);
                    }
                }
                catch (InvalidKeyException e)
                {
                    throw new Exception(e.Message);
                }
            }

            return cipher.encrypt(signalProtocolAddress, plaintext, legacy, silent);
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