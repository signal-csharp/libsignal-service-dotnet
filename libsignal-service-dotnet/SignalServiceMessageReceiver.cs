using libsignalservice.messages;
using libsignalservice.push;
using libsignalservice.util;
using libsignalservice.websocket;
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
        private static int BLOCK_SIZE = 16;
        private static int CIPHER_KEY_SIZE = 32;
        private static int MAC_KEY_SIZE = 32;
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
        /// <param name="plaintextDestination">The download destination for this attachment.</param>
        /// <param name="tmpCipherDestination">The temporary destination for this attachment before decryption</param>
        public void retrieveAttachment(SignalServiceAttachmentPointer pointer, FileStream plaintextDestination, FileStream tmpCipherDestination)
        {
            retrieveAttachment(pointer, plaintextDestination, tmpCipherDestination, 80 * 1024 * 1024, null);
        }

        /// <summary>
        /// Retrieves a SignalServiceAttachment
        /// </summary>
        /// <param name="pointer">The <see cref="SignalServiceAttachmentPointer"/>
        /// received in a <see cref="SignalServiceDataMessage"/></param>
        /// <param name="plaintextDestination">The download destination for this attachment.</param>
        /// <param name="tmpCipherDestination">The temporary destination for this attachment before decryption</param>
        /// <param name="maxSizeBytes">The maximum size for this attachment (not yet implemented)</param>
        /// <param name="listener">An optional listener (may be null) to receive callbacks on download progress.</param>
        public void retrieveAttachment(SignalServiceAttachmentPointer pointer, FileStream plaintextDestination, FileStream tmpCipherDestination, int maxSizeBytes, ProgressListener listener)
        {
            socket.retrieveAttachment(pointer.getRelay(), pointer.getId(), tmpCipherDestination, maxSizeBytes);
            tmpCipherDestination.Seek(0, SeekOrigin.Begin);

            byte[] combinedKeyMaterial = pointer.getKey();
            byte[][] parts = Util.split(combinedKeyMaterial, CIPHER_KEY_SIZE, MAC_KEY_SIZE);
            //byte[] digest = pointer.getDigest(); //TODO
            //verifyMac()

            byte[] iv = new byte[BLOCK_SIZE];
            Util.readFully(tmpCipherDestination, iv);

            using (var aes = Aes.Create())
            {
                aes.Key = parts[0];
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (var decrypt = aes.CreateDecryptor())
                using (var cryptoStream = new CryptoStream(tmpCipherDestination, decrypt, CryptoStreamMode.Read))
                {
                    byte[] buffer = new byte[CIPHER_KEY_SIZE];
                    int read = cryptoStream.Read(buffer, 0, buffer.Length);
                    while (read > 0)
                    {
                        plaintextDestination.Write(buffer, 0, read);
                        read = cryptoStream.Read(buffer, 0, buffer.Length);
                    }
                }
            }
        }

        /// <summary>
        /// Creates a pipe for receiving SignalService messages.
        ///
        /// Callers must call <see cref="SignalServiceMessagePipe.Shutdown()"/> when finished with the pipe.
        /// </summary>
        /// <returns>A SignalServiceMessagePipe for receiving Signal Service messages.</returns>
        public SignalServiceMessagePipe createMessagePipe()
        {
            SignalWebSocketConnection webSocket = new SignalWebSocketConnection(Token, urls[0].getUrl(), credentialsProvider, userAgent);
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
