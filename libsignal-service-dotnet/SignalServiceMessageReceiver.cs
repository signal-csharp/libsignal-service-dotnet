using libsignal;
using libsignal.push;
using libsignal.util;
using libsignalservice.configuration;
using libsignalservice.crypto;
using libsignalservice.messages;
using libsignalservice.profiles;
using libsignalservice.push;
using libsignalservice.util;
using libsignalservice.websocket;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using static libsignalservice.messages.SignalServiceAttachment;

namespace libsignalservice
{
    /// <summary>
    /// The primary interface for receiving Signal Service messages.
    /// </summary>
    public class SignalServiceMessageReceiver
    {
        private const int BLOCK_SIZE = 16;
        private const int CIPHER_KEY_SIZE = 32;
        private const int MAC_KEY_SIZE = 32;
        private readonly PushServiceSocket Socket;
        private readonly SignalServiceConfiguration Urls;
        private readonly CredentialsProvider credentialsProvider;
        private readonly string UserAgent;
        private readonly CancellationToken Token;

        /// <summary>
        /// Construct a SignalServiceMessageReceiver.
        /// </summary>
        /// <param name="urls">The URL of the Signal Service.</param>
        /// <param name="credentials">The Signal Service user's credentials</param>
        /// <param name="userAgent"></param>
        public SignalServiceMessageReceiver(CancellationToken token, SignalServiceConfiguration urls, CredentialsProvider credentials, string userAgent)
        {
            this.Token = token;
            this.Urls = urls;
            this.credentialsProvider = credentials;
            this.Socket = new PushServiceSocket(urls, credentials, userAgent);
            this.UserAgent = userAgent;
        }

        public SignalServiceProfile RetrieveProfile(SignalServiceAddress address)
        {
            return Socket.RetrieveProfile(address);
        }

        /// <summary>
        /// Retrieves a SignalServiceAttachment
        /// </summary>
        /// <param name="pointer">The <see cref="SignalServiceAttachmentPointer"/>
        /// received in a <see cref="SignalServiceDataMessage"/></param>
        /// <param name="plaintextDestination">The download destination for this attachment.</param>
        /// <param name="tmpCipherDestination">The temporary destination for this attachment before decryption</param>
        public Stream RetrieveAttachment(SignalServiceAttachmentPointer pointer, Stream tmpCipherDestination, int maxSizeBytes)
        {
            return RetrieveAttachment(pointer, tmpCipherDestination, maxSizeBytes, null);
        }

        /// <summary>
        /// Retrieves a SignalServiceAttachment
        /// </summary>
        /// <param name="pointer">The <see cref="SignalServiceAttachmentPointer"/>
        /// received in a <see cref="SignalServiceDataMessage"/></param>
        /// <param name="tmpCipherDestination">The temporary destination for this attachment before decryption</param>
        /// <param name="maxSizeBytes">The maximum size for this attachment (not yet implemented)</param>
        /// <param name="listener">An optional listener (may be null) to receive callbacks on download progress.</param>
        public Stream RetrieveAttachment(SignalServiceAttachmentPointer pointer, Stream tmpCipherDestination, int maxSizeBytes, ProgressListener listener)
        {
            Socket.RetrieveAttachment(pointer.Relay, pointer.Id, tmpCipherDestination, maxSizeBytes);
            return new AttachmentCipherInputStream(tmpCipherDestination, pointer.Key, pointer.Digest);
        }

        /// <summary>
        /// Retrieves an attachment URL location
        /// </summary>
        /// <param name="pointer">The pointer to the attachment</param>
        /// <returns></returns>
        public string RetrieveAttachmentDownloadUrl(SignalServiceAttachmentPointer pointer)
        {
            return Socket.RetrieveAttachmentDownloadUrl(pointer.Relay, pointer.Id);
        }

        /// <summary>
        /// Creates a pipe for receiving SignalService messages.
        ///
        /// Callers must call <see cref="SignalServiceMessagePipe.Shutdown()"/> when finished with the pipe.
        /// </summary>
        /// <returns>A SignalServiceMessagePipe for receiving Signal Service messages.</returns>
        public SignalServiceMessagePipe CreateMessagePipe()
        {
            SignalWebSocketConnection webSocket = new SignalWebSocketConnection(Token, Urls.SignalServiceUrls[0].Url, credentialsProvider, UserAgent);
            return new SignalServiceMessagePipe(Token, webSocket, credentialsProvider);
        }

        public List<SignalServiceEnvelope> RetrieveMessages(MessageReceivedCallback callback)
        {
            List<SignalServiceEnvelope> results = new List<SignalServiceEnvelope>();
            List<SignalServiceEnvelopeEntity> entities = Socket.getMessages();

            foreach (SignalServiceEnvelopeEntity entity in entities)
            {
                SignalServiceEnvelope envelope = new SignalServiceEnvelope((int)entity.getType(), entity.getSource(),
                                                                      (int)entity.getSourceDevice(), entity.getRelay(),
                                                                      (int)entity.getTimestamp(), entity.getMessage(),
                                                                      entity.getContent());

                callback.onMessage(envelope);
                results.Add(envelope);

                Socket.acknowledgeMessage(entity.getSource(), entity.getTimestamp());
            }
            return results;
        }

        public interface MessageReceivedCallback
        {
            void onMessage(SignalServiceEnvelope envelope);
        }
    }
}
