/** 
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
using System.IO;
using System.Threading.Tasks;
using libsignalservice.messages;
using libsignalservice.push;
using libsignalservice.util;
using libsignalservice.websocket;
using static libsignalservice.messages.SignalServiceAttachment;

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

        /// <summary>
        /// Construct a SignalServiceMessageReceiver
        /// </summary>
        /// <param name="urls">The URL of the Signal Service.</param>
        /// the server's TLS signing certificate</param>
        /// <param name="user">The Signal Service username (eg. phone number).</param>
        /// <param name="password">The Signal Service user password.</param>
        /// <param name="signalingKey">The 52 byte signaling key assigned to this user at registration</param>
        /// <param name="userAgent"></param>
        public SignalServiceMessageReceiver(SignalServiceUrl[] urls,
                                         string user, string password, string signalingKey, string userAgent)
            : this(urls, new StaticCredentialsProvider(user, password, signalingKey), userAgent)
        {
        }

        /// <summary>
        /// Construct a SignalServiceMessageReceiver.
        /// </summary>
        /// <param name="urls">The URL of the Signal Service.</param>
        /// <param name="credentials">The Signal Service user's credentials</param>
        /// <param name="userAgent"></param>
        public SignalServiceMessageReceiver(SignalServiceUrl[] urls, CredentialsProvider credentials, string userAgent)
        {
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
        /// Callers must call <see cref="SignalServiceMessagePipe.shutdown()"/> when finished with the pipe.
        /// </summary>
        /// <returns>A SignalServiceMessagePipe for receiving Signal Service messages.</returns>
        public SignalServiceMessagePipe createMessagePipe()
        {
            WebSocketConnection webSocket = new WebSocketConnection(urls[0].getUrl(), urls[0].getTrustStore(), credentialsProvider, userAgent);
            return new SignalServiceMessagePipe(webSocket, credentialsProvider);
        }

        public List<SignalServiceEnvelope> retrieveMessages()
        {
            return retrieveMessages(new NullMessageReceivedCallback());
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

        public class NullMessageReceivedCallback : MessageReceivedCallback
        {
            public void onMessage(SignalServiceEnvelope envelope) { }
        }

    }
}
