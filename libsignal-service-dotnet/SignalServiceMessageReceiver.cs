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
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using static libsignalservice.messages.SignalServiceAttachment;
using static libsignalservice.SignalServiceMessagePipe;

namespace libsignalservice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
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
        private readonly CredentialsProvider CredentialsProvider;
        private readonly string UserAgent;
        private readonly ConnectivityListener ConnectivityListener;
        private readonly CancellationToken Token;

        /// <summary>
        /// Construct a SignalServiceMessageReceiver.
        /// </summary>
        /// <param name="token">A CancellationToken to cancel the receiver's operations</param>
        /// <param name="urls">The URL of the Signal Service.</param>
        /// <param name="credentials">The Signal Service user's credentials</param>
        /// <param name="userAgent"></param>
        /// <param name="connectivityListener"></param>
        public SignalServiceMessageReceiver(CancellationToken token, SignalServiceConfiguration urls, CredentialsProvider credentials, string userAgent, ConnectivityListener connectivityListener)
        {
            Token = token;
            Urls = urls;
            CredentialsProvider = credentials;
            Socket = new PushServiceSocket(urls, credentials, userAgent);
            UserAgent = userAgent;
            ConnectivityListener = connectivityListener;
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="address"></param>
        /// <returns></returns>
        public SignalServiceProfile RetrieveProfile(SignalServiceAddress address)
        {
            return Socket.RetrieveProfile(address);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="path"></param>
        /// <param name="destination"></param>
        /// <param name="profileKey"></param>
        /// <param name="maxSizeBytes"></param>
        /// <returns></returns>
        public Stream RetrieveProfileAvatar(string path, FileStream destination, byte[] profileKey, int maxSizeBytes)
        {
            Socket.RetrieveProfileAvatar(path, destination, maxSizeBytes);
            destination.Seek(0, SeekOrigin.Begin);
            return new ProfileCipherInputStream(destination, profileKey);
        }

        /// <summary>
        /// Retrieves a SignalServiceAttachment
        /// </summary>
        /// <param name="pointer">The <see cref="SignalServiceAttachmentPointer"/>
        /// received in a <see cref="SignalServiceDataMessage"/></param>
        /// <param name="tmpCipherDestination">The temporary destination for this attachment before decryption</param>
        /// <param name="maxSizeBytes">The maximum size for this attachment (not yet implemented)</param>
        /// <param name="listener">An optional listener (may be null) to receive callbacks on download progress.</param>
        public Stream RetrieveAttachment(SignalServiceAttachmentPointer pointer, Stream tmpCipherDestination, int maxSizeBytes, IProgressListener listener)
        {
            Socket.RetrieveAttachment(pointer.Relay, pointer.Id, tmpCipherDestination, maxSizeBytes);
            tmpCipherDestination.Position = 0;
            return AttachmentCipherInputStream.CreateFor(tmpCipherDestination, pointer.Size != null ? pointer.Size.Value : 0, pointer.Key, pointer.Digest);
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
            SignalWebSocketConnection webSocket = new SignalWebSocketConnection(Token, Urls.SignalServiceUrls[0].Url, CredentialsProvider, UserAgent, ConnectivityListener);
            return new SignalServiceMessagePipe(Token, webSocket, CredentialsProvider);
        }

        public List<SignalServiceEnvelope> RetrieveMessages(IMessagePipeCallback callback)
        {
            List<SignalServiceEnvelope> results = new List<SignalServiceEnvelope>();
            List<SignalServiceEnvelopeEntity> entities = Socket.GetMessages();

            foreach (SignalServiceEnvelopeEntity entity in entities)
            {
                SignalServiceEnvelope envelope = new SignalServiceEnvelope((int)entity.Type, entity.Source,
                                                                      (int)entity.SourceDevice, entity.Relay,
                                                                      (int)entity.Timestamp, entity.Message,
                                                                      entity.Content);

                callback.OnMessage(envelope);
                results.Add(envelope);

                Socket.AcknowledgeMessage(entity.Source, entity.Timestamp);
            }
            return results;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
