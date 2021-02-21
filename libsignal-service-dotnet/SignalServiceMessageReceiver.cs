using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using libsignal;
using libsignalservice.configuration;
using libsignalservice.crypto;
using libsignalservice.messages;
using libsignalservice.profiles;
using libsignalservice.push;
using libsignalservice.util;
using libsignalservice.websocket;
using libsignalservicedotnet.crypto;
using static libsignalservice.messages.SignalServiceAttachment;
using static libsignalservice.SignalServiceMessagePipe;

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
        private readonly ICredentialsProvider CredentialsProvider;
        private readonly string UserAgent;

        /// <summary>
        /// Construct a SignalServiceMessageReceiver.
        /// </summary>
        /// <param name="urls">The URL of the Signal Service.</param>
        /// <param name="credentials">The Signal Service user's credentials</param>
        /// <param name="userAgent"></param>
        public SignalServiceMessageReceiver(SignalServiceConfiguration urls, ICredentialsProvider credentials, string userAgent, HttpClient httpClient)
        {
            Urls = urls;
            CredentialsProvider = credentials;
            Socket = new PushServiceSocket(urls, credentials, userAgent, httpClient);
            UserAgent = userAgent;
        }

        /// <summary>
        /// Retrieves a SignalServiceAttachment.
        /// </summary>
        /// <param name="pointer">The <see cref="SignalServiceAttachmentPointer"/> received in a <see cref="SignalServiceDataMessage"/>.</param>
        /// <param name="destination">The download destination for this attachment.</param>
        /// <param name="maxSizeBytes"></param>
        /// <param name="token"></param>
        /// <returns>A Stream that streams the plaintext attachment contents.</returns>
        /// <exception cref="IOException"></exception>
        /// <exception cref="InvalidMessageException"></exception>
        public async Task<Stream> RetrieveAttachmentAsync(SignalServiceAttachmentPointer pointer, FileStream destination, int maxSizeBytes, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            return await RetrieveAttachment(pointer, destination, maxSizeBytes, null, token);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="token"></param>
        /// <param name="address"></param>
        /// <param name="unidentifiedAccess"></param>
        /// <returns></returns>
        public async Task<SignalServiceProfile> RetrieveProfile(CancellationToken token, SignalServiceAddress address, UnidentifiedAccess? unidentifiedAccess)
        {
            return await Socket.RetrieveProfile(address, unidentifiedAccess, token);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="path"></param>
        /// <param name="destination"></param>
        /// <param name="profileKey"></param>
        /// <param name="maxSizeBytes"></param>
        /// <returns></returns>
        public async Task<Stream> RetrieveProfileAvatarAsync(string path, FileStream destination, byte[] profileKey, int maxSizeBytes, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await Socket.RetrieveProfileAvatarAsync(path, destination, maxSizeBytes, token);
            destination.Seek(0, SeekOrigin.Begin);
            return new ProfileCipherInputStream(destination, profileKey);
        }

        /// <summary>
        /// Retrieves a SignalServiceAttachment
        /// </summary>
        /// <param name="pointer">The <see cref="SignalServiceAttachmentPointer"/>
        /// received in a <see cref="SignalServiceDataMessage"/></param>
        /// <param name="destination">The download destination for this attachment.</param>
        /// <param name="maxSizeBytes"></param>
        /// <param name="listener">An optional listener (may be null) to receive callbacks on download progress.</param>
        /// <param name="token"></param>
        /// <exception cref="IOException"></exception>
        /// <exception cref="InvalidMessageException"></exception>
        public async Task<Stream> RetrieveAttachment(SignalServiceAttachmentPointer pointer, FileStream destination, int maxSizeBytes, IProgressListener? listener, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            if (pointer.Digest == null) throw new InvalidMessageException("No attachment digest!");

            await Socket.RetrieveAttachmentAsync((long)pointer.Id, destination, maxSizeBytes, listener, token);
            destination.Position = 0;
            return AttachmentCipherInputStream.CreateFor(destination, pointer.Size != null ? pointer.Size.Value : 0, pointer.Key, pointer.Digest);
        }

        /// <summary>
        /// Creates a pipe for receiving SignalService messages.
        ///
        /// Callers must call <see cref="SignalServiceMessagePipe.Shutdown()"/> when finished with the pipe.
        /// </summary>
        /// <returns>A SignalServiceMessagePipe for receiving Signal Service messages.</returns>
        public async Task<SignalServiceMessagePipe> CreateMessagePipe(CancellationToken token, ISignalWebSocketFactory webSocketFactory)
        {
            SignalWebSocketConnection webSocket = new SignalWebSocketConnection(token, Urls.SignalServiceUrls[0].Url,
                CredentialsProvider, UserAgent, webSocketFactory);
            var messagePipe = new SignalServiceMessagePipe(token, webSocket, CredentialsProvider, webSocketFactory);
            await messagePipe.Connect();
            return messagePipe;
        }

        /// <summary>
        /// Creates an unidentified message pipe.
        ///
        /// Callers must call <see cref="SignalServiceMessagePipe.Shutdown()"/> when finished with the pipe.
        /// </summary>
        /// <returns>A SignalServiceMessagePipe for receiving Signal Service messages.</returns>
        public async Task<SignalServiceMessagePipe> CreateUnidentifiedMessagePipe(CancellationToken token, ISignalWebSocketFactory webSocketFactory)
        {
            SignalWebSocketConnection webSocket = new SignalWebSocketConnection(token, Urls.SignalServiceUrls[0].Url,
                null, UserAgent, webSocketFactory);
            var messagePipe = new SignalServiceMessagePipe(token, webSocket, CredentialsProvider, webSocketFactory);
            await messagePipe.Connect();
            return messagePipe;
        }

        public async Task<List<SignalServiceEnvelope>> RetrieveMessages(CancellationToken token, IMessagePipeCallback callback)
        {
            List<SignalServiceEnvelope> results = new List<SignalServiceEnvelope>();
            List<SignalServiceEnvelopeEntity> entities = await Socket.GetMessages(token);

            foreach (SignalServiceEnvelopeEntity entity in entities)
            {
                SignalServiceEnvelope envelope;

                if (entity.Source != null && entity.SourceDevice > 0)
                {
                    envelope = new SignalServiceEnvelope((int) entity.Type, entity.Source,
                                                         (int) entity.SourceDevice, (int) entity.Timestamp,
                                                         entity.Message, entity.Content,
                                                         entity.ServerTimestamp, entity.ServerUuid);
                }
                else
                {
                    envelope = new SignalServiceEnvelope((int) entity.Type, (int) entity.Timestamp,
                                                         entity.Message, entity.Content,
                                                         entity.ServerTimestamp, entity.ServerUuid);
                }

                await callback.OnMessage(envelope);
                results.Add(envelope);

                if (envelope.HasUuid()) await Socket.AcknowledgeMessage(token, envelope.GetUuid());
                else await Socket.AcknowledgeMessage(token, entity.Source, entity.Timestamp);
            }
            return results;
        }
    }
}
