using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using libsignalservice.messages;
using libsignalservice.push;
using libsignalservice.util;
using libsignalservice.websocket;
using static libsignalservice.messages.SignalServiceAttachment;
using System.Threading;

namespace libsignalservice
{
    /// <summary>
    /// The primary interface for receiving Signal Service messages.
    /// </summary>
    public class SignalServiceMessageReceiver
    {
        private readonly PushServiceSocket socket;
        private readonly SignalServiceUrl[] urls;
        private readonly CredentialsProvider credentialsProvider;
        private readonly string userAgent;
        private readonly CancellationToken Token;

        /// <summary>
        /// Construct a SignalServiceMessageReceiver.
        /// </summary>
        /// <param name="urls">The URL of the Signal Service.</param>
        /// <param name="credentials">The Signal Service user's credentials</param>
        /// <param name="userAgent"></param>
        public SignalServiceMessageReceiver(CancellationToken token, SignalServiceUrl[] urls, CredentialsProvider credentials, string userAgent)
        {
            this.Token = token;
            this.urls = urls;
            this.credentialsProvider = credentials;
            this.socket = new PushServiceSocket(urls, credentials, userAgent);
            this.userAgent = userAgent;
        }

        /// <summary>
        /// Retrieves a SignalServiceAttachment
        /// </summary>
        /// <param name="pointer">The <see cref="SignalServiceAttachmentPointer"/>
        /// received in a <see cref="SignalServiceDataMessage"/></param>
        /// <param name="destination">The download destination for this attachment.</param>
        /// <returns>A Stream that streams the plaintext attachment contents.</returns>
        public Stream retrieveAttachment(SignalServiceAttachmentPointer pointer, FileStream destination)
        {
            throw new NotImplementedException();
            return retrieveAttachment(pointer, destination, null);
        }

        /// <summary>
        /// Retrieves a SignalServiceAttachment
        /// </summary>
        /// <param name="pointer">The <see cref="SignalServiceAttachmentPointer"/>
        /// received in a <see cref="SignalServiceDataMessage"/></param>
        /// <param name="destination">The download destination for this attachment.</param>
        /// <param name="listener">An optional listener (may be null) to receive callbacks on download progress.</param>
        /// <returns>A Stream that streams the plaintext attachment contents.</returns>
        public Stream retrieveAttachment(SignalServiceAttachmentPointer pointer, FileStream destination, ProgressListener listener)
        {
            throw new NotImplementedException();
            return new MemoryStream();
        }

        /// <summary>
        /// Creates a pipe for receiving SignalService messages.
        /// 
        /// Callers must call <see cref="SignalServiceMessagePipe.Shutdown()"/> when finished with the pipe.
        /// </summary>
        /// <returns>A SignalServiceMessagePipe for receiving Signal Service messages.</returns>
        public SignalServiceMessagePipe createMessagePipe()
        {
            SignalWebSocketConnection webSocket = new SignalWebSocketConnection(Token, urls[0].getUrl(), urls[0].getTrustStore(), credentialsProvider, userAgent);
            return new SignalServiceMessagePipe(Token, webSocket, credentialsProvider);
        }

        public List<SignalServiceEnvelope> retrieveMessages(MessageReceivedCallback callback)
        {
            List<SignalServiceEnvelope> results = new List<SignalServiceEnvelope>();
            List<SignalServiceEnvelopeEntity> entities = socket.getMessages();

            foreach (SignalServiceEnvelopeEntity entity in entities)
            {
                SignalServiceEnvelope envelope = new SignalServiceEnvelope((int)entity.getType(), entity.getSource(),
                                                                      (int)entity.getSourceDevice(), entity.getRelay(),
                                                                      (int)entity.getTimestamp(), entity.getMessage(),
                                                                      entity.getContent());

                callback.onMessage(envelope);
                results.Add(envelope);

                socket.acknowledgeMessage(entity.getSource(), entity.getTimestamp());
            }
            return results;
        }


        public interface MessageReceivedCallback
        {
            void onMessage(SignalServiceEnvelope envelope);
        }
    }
}
