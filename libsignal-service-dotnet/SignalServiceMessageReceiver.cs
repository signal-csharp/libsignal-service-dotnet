using System;
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

        public SignalServiceMessageReceiver(SignalServiceConfiguration urls,
            Guid uuid, string e164, string password, int deviceId,
            string userAgent, HttpClient httpClient) :
            this(urls, new StaticCredentialsProvider(uuid, e164, password, deviceId), userAgent, httpClient)
        {
        }

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
        public async Task<Stream> RetrieveAttachmentAsync(SignalServiceAttachmentPointer pointer, Stream destination, int maxSizeBytes, CancellationToken? token = null)
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
        public async Task<Stream> RetrieveProfileAvatarAsync(string path, Stream destination, byte[] profileKey, int maxSizeBytes, CancellationToken? token = null)
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
        public async Task<Stream> RetrieveAttachment(SignalServiceAttachmentPointer pointer, Stream destination, int maxSizeBytes, IProgressListener? listener, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            if (pointer.Digest == null) throw new InvalidMessageException("No attachment digest!");

            await Socket.RetrieveAttachmentAsync(pointer.CdnNumber, pointer.RemoteId, destination, maxSizeBytes, listener, token);
            destination.Position = 0;
            return AttachmentCipherInputStream.CreateForAttachment(destination, pointer.Size != null ? pointer.Size.Value : 0, pointer.Key, pointer.Digest);
        }

        public string RetrieveAttachmentDownloadUrl(SignalServiceAttachmentPointer pointer)
        {
            return Socket.RetrieveAttachmentDownloadUrl(pointer.CdnNumber, pointer.RemoteId);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="packId"></param>
        /// <param name="packKey"></param>
        /// <param name="stickerId"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        /// <exception cref="InvalidMessageException"></exception>
        public async Task<Stream> RetrieveStickerAsync(byte[] packId, byte[] packKey, int stickerId, CancellationToken? token = null)
        {
            byte[] data = await Socket.RetrieveStickerAsync(packId, stickerId, token);
            return AttachmentCipherInputStream.CreateForStickerData(data, packKey);
        }

        /// <summary>
        /// Retrieves a <see cref="SignalServiceStickerManifest"/>.
        /// </summary>
        /// <param name="packId">The 16-byte packId that identifies the sticker pack.</param>
        /// <param name="packKey">The 32-byte packKey that decrypts the sticker pack.</param>
        /// <param name="token">Cancellation token, may be null.</param>
        /// <returns>The <see cref="SignalServiceStickerManifest"/> representing the sticker pack.</returns>
        /// <exception cref="IOException"></exception>
        /// <exception cref="InvalidMessageException"></exception>
        public async Task<SignalServiceStickerManifest> RetrieveStickerManifestAsync(byte[] packId, byte[] packKey, CancellationToken? token = null)
        {
            byte[] manifestBytes = await Socket.RetrieveStickerManifestAsync(packId, token);

            Stream cipherStream = AttachmentCipherInputStream.CreateForStickerData(manifestBytes, packKey);
            MemoryStream outputStream = new MemoryStream();

            Util.Copy(cipherStream, outputStream);

            sticker.Pack pack = sticker.Pack.Parser.ParseFrom(outputStream.ToArray());
            List<SignalServiceStickerManifest.StickerInfo> stickers = new List<SignalServiceStickerManifest.StickerInfo>(pack.Stickers.Count);
            SignalServiceStickerManifest.StickerInfo? cover = pack.Cover != null ? new SignalServiceStickerManifest.StickerInfo((int)pack.Cover.Id, pack.Cover.Emoji) : null;

            foreach (sticker.Pack.Types.Sticker sticker in pack.Stickers)
            {
                stickers.Add(new SignalServiceStickerManifest.StickerInfo((int)sticker.Id, sticker.Emoji));
            }

            return new SignalServiceStickerManifest(pack.Title, pack.Author, cover, stickers);
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

                if (entity.HasSource() && entity.SourceDevice > 0)
                {
                    SignalServiceAddress address = new SignalServiceAddress(UuidUtil.ParseOrNull(entity.SourceUuid), entity.SourceE164);
                    envelope = new SignalServiceEnvelope((int) entity.Type, address,
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
                else await Socket.AcknowledgeMessage(token, entity.SourceE164!, entity.Timestamp);
            }
            return results;
        }
    }
}
