using libsignal.push;
using libsignal.util;
using libsignalservice.messages;
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

        public SignalServiceProfile RetrieveProfile(SignalServiceAddress address)
        {
            return socket.RetrieveProfile(address);
        }

        /// <summary>
        /// Retrieves a SignalServiceAttachment
        /// </summary>
        /// <param name="pointer">The <see cref="SignalServiceAttachmentPointer"/>
        /// received in a <see cref="SignalServiceDataMessage"/></param>
        /// <param name="plaintextDestination">The download destination for this attachment.</param>
        /// <param name="tmpCipherDestination">The temporary destination for this attachment before decryption</param>
        public void retrieveAttachment(SignalServiceAttachmentPointer pointer, Stream plaintextDestination, Stream tmpCipherDestination, int maxSizeBytes)
        {
            retrieveAttachment(pointer, plaintextDestination, tmpCipherDestination, maxSizeBytes, null);
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
        public void retrieveAttachment(SignalServiceAttachmentPointer pointer, Stream plaintextDestination, Stream tmpCipherDestination, int maxSizeBytes, ProgressListener listener)
        {
            socket.retrieveAttachment(pointer.Relay, pointer.Id, tmpCipherDestination, maxSizeBytes);
            tmpCipherDestination.Seek(0, SeekOrigin.Begin);
            DecryptAttachment(pointer, tmpCipherDestination, plaintextDestination);
        }

        /// <summary>
        /// Retrieves an attachment URL location
        /// </summary>
        /// <param name="pointer">The pointer to the attachment</param>
        /// <returns></returns>
        public string RetrieveAttachmentDownloadUrl(SignalServiceAttachmentPointer pointer)
        {
            return socket.RetrieveAttachmentDownloadUrl(pointer.Relay, pointer.Id);
        }

        /// <summary>
        /// Decrypts an attachment
        /// </summary>
        /// <param name="pointer">The pointer for the attachment</param>
        /// <param name="cipherStream">The input encrypted stream</param>
        /// <param name="plaintextStream">The output decrypted stream</param>
        public void DecryptAttachment(SignalServiceAttachmentPointer pointer, Stream cipherStream, Stream plaintextStream)
        {
            byte[] combinedKeyMaterial = pointer.Key;
            byte[][] parts = Util.split(combinedKeyMaterial, CIPHER_KEY_SIZE, MAC_KEY_SIZE);

            if (pointer.Digest != null)
            {
                using (HMAC mac = new HMACSHA256(parts[1]))
                {
                    VerifyMac(cipherStream, mac, pointer.Digest);
                }
            }

            byte[] iv = new byte[BLOCK_SIZE];
            cipherStream.Seek(0, SeekOrigin.Begin);
            Util.readFully(cipherStream, iv);

            using (var aes = Aes.Create())
            {
                aes.Key = parts[0];
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (var decrypt = aes.CreateDecryptor())
                using (var cryptoStream = new CryptoStream(cipherStream, decrypt, CryptoStreamMode.Read))
                {
                    byte[] buffer = new byte[CIPHER_KEY_SIZE];
                    int read = cryptoStream.Read(buffer, 0, buffer.Length);
                    while (read > 0)
                    {
                        plaintextStream.Write(buffer, 0, read);
                        read = cryptoStream.Read(buffer, 0, buffer.Length);
                    }
                }
            }
        }

        /// <summary>
        /// Verifies an attachment
        /// </summary>
        /// <param name="stream">The encrypted stream</param>
        /// <param name="mac">A MAC</param>
        /// <param name="theirDigest">The received digest</param>
        private void VerifyMac(Stream stream, HMAC mac, byte[] theirDigest)
        {
            using (SHA256 digest = SHA256.Create())
            {
                // Determine the file length (total file - the mac at the end (32 bytes))
                int remainingData = Util.toIntExact(stream.Length) - mac.Key.Length;
                byte[] buffer = new byte[4096];
                byte[] ourMac = new byte[0];

                // Read the data into a memory stream because we can only get the hash on an entire set of data
                MemoryStream memoryStream = new MemoryStream(remainingData);
                while (remainingData > 0)
                {
                    int read = stream.Read(buffer, 0, Math.Min(buffer.Length, remainingData));
                    memoryStream.Write(buffer, 0, read);
                    remainingData -= read;
                }

                // Get the hash for the file
                memoryStream.Seek(0, SeekOrigin.Begin);
                ourMac = mac.ComputeHash(memoryStream);

                // Then read the rest of the file (the MAC) and check if the hashes are the same
                byte[] theirMac = new byte[mac.Key.Length];
                Util.readFully(stream, theirMac);
                if (!ByteUtil.isEqual(ourMac, theirMac))
                {
                    throw new Exception("MAC doesn't match");
                }

                // Then compare the digests by hashing the entire file
                stream.Seek(0, SeekOrigin.Begin);
                byte[] ourDigest = digest.ComputeHash(stream);
                if (!ByteUtil.isEqual(ourDigest, theirDigest))
                {
                    throw new Exception("Digest doesn't match");
                }

                // Finally throw the MAC at the end away
                stream.SetLength(stream.Length - mac.Key.Length);
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
