using Google.Protobuf;
using libsignal;
using libsignal.util;
using libsignalservice.push;
using libsignalservice.util;

using System;
using System.Linq;
using static libsignalservice.SignalServiceMessagePipe;

namespace libsignalservice.messages
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    /// <summary>
    /// This class represents an encrypted Signal Service envelope.
    ///
    /// The envelope contains the wrapping information, such as the sender, the
    /// message timestamp, the encrypted message type, etc.
    /// </summary>
    public class SignalServiceEnvelope: SignalServiceMessagePipeMessage
    {
        private static readonly int SUPPORTED_VERSION = 1;
        private static readonly int CIPHER_KEY_SIZE = 32;
        private static readonly int MAC_KEY_SIZE = 20;
        private static readonly int MAC_SIZE = 10;

        private static readonly int VERSION_OFFSET = 0;
        private static readonly int VERSION_LENGTH = 1;
        private static readonly int IV_OFFSET = VERSION_OFFSET + VERSION_LENGTH;
        private static readonly int IV_LENGTH = 16;
        private static readonly int CIPHERTEXT_OFFSET = IV_OFFSET + IV_LENGTH;

        private readonly Envelope envelope;


        public SignalServiceEnvelope(String message, String signalingKey)
            : this(Base64.Decode(message), signalingKey)
        {
        }

        /// <summary>
        /// Construct an envelope from a serialized SignalServiceEnvelope, encrypted with a signaling key.
        /// </summary>
        /// <param name="ciphertext">The serialized and encrypted SignalServiceEnvelope.</param>
        /// <param name="signalingKey">The signaling key.</param>
        public SignalServiceEnvelope(byte[] ciphertext, string signalingKey)//throws InvalidVersionException, IOException
        {
            if (ciphertext.Length < VERSION_LENGTH || ciphertext[VERSION_OFFSET] != SUPPORTED_VERSION)
                throw new InvalidVersionException("Unsupported version!");

            byte[] cipherKey = GetCipherKey(signalingKey);
            byte[] macKey = GetMacKey(signalingKey);

            VerifyMac(ciphertext, macKey);

            envelope = Envelope.Parser.ParseFrom(GetPlaintext(ciphertext, cipherKey));
        }

        public SignalServiceEnvelope(int type, string source, int sourceDevice,
            string relay, long timestamp, byte[] legacyMessage, byte[] content)
        {
            Envelope envelope = new Envelope
            {
                Type = (Envelope.Types.Type)type,
                Source = source,
                SourceDevice = (uint)sourceDevice,
                Relay = relay,
                Timestamp = (ulong)timestamp
            };

            if (legacyMessage != null) envelope.LegacyMessage = ByteString.CopyFrom(legacyMessage);
            if (content != null) envelope.Content = ByteString.CopyFrom(content);

            this.envelope = envelope;
        }

        /// <summary>
        /// The envelope's sender.
        /// </summary>
        /// <returns>The envelope's sender.</returns>
        public string GetSource()
        {
            return envelope.Source;
        }

        /// <summary>
        /// The envelope's sender device ID.
        /// </summary>
        /// <returns>The envelope's sender device ID.</returns>
        public int GetSourceDevice()
        {
            return (int)envelope.SourceDevice;
        }

        /// <summary>
        /// The envelope's sender as a SignalServiceAddress.
        /// </summary>
        /// <returns>The envelope's sender as a SignalServiceAddress.</returns>
        public SignalServiceAddress GetSourceAddress()
        {
            return new SignalServiceAddress(envelope.Source, envelope.RelayOneofCase == Envelope.RelayOneofOneofCase.Relay ? envelope.Relay : null);
        }

        /// <summary>
        /// The envelope content type.
        /// </summary>
        /// <returns>The envelope content type.</returns>
        public int GetEnvelopeType()
        {
            return (int)envelope.Type;
        }

        /// <summary>
        /// The federated server this envelope came from.
        /// </summary>
        /// <returns>The federated server this envelope came from.</returns>
        public string GetRelay()
        {
            return envelope.Relay;
        }

        /// <summary>
        /// The timestamp this envelope was sent.
        /// </summary>
        /// <returns>The timestamp this envelope was sent.</returns>
        public long GetTimestamp()
        {
            return (long)envelope.Timestamp;
        }

        /// <summary>
        /// Whether the envelope contains a SignalServiceDataMessage
        /// </summary>
        /// <returns>Whether the envelope contains a SignalServiceDataMessage</returns>
        public bool HasLegacyMessage()
        {
            return envelope.LegacyMessageOneofCase == Envelope.LegacyMessageOneofOneofCase.LegacyMessage;
        }

        /// <summary>
        /// The envelope's containing SignalService message.
        /// </summary>
        /// <returns>The envelope's containing SignalService message.</returns>
        public byte[] GetLegacyMessage()
        {
            return envelope.LegacyMessage.ToByteArray();
        }

        /// <summary>
        /// Whether the envelope contains an encrypted SignalServiceContent
        /// </summary>
        /// <returns>Whether the envelope contains an encrypted SignalServiceContent</returns>
        public bool HasContent()
        {
            return envelope.ContentOneofCase == Envelope.ContentOneofOneofCase.Content;
        }

        /// <summary>
        /// The envelope's containing message.
        /// </summary>
        /// <returns>The envelope's containing message.</returns>
        public byte[] GetContent()
        {
            return envelope.Content.ToByteArray();
        }

        /// <summary>
        /// True if the containing message is a <see cref="libsignal.protocol.SignalMessage"/>
        /// </summary>
        /// <returns>True if the containing message is a <see cref="libsignal.protocol.SignalMessage"/></returns>
        public bool IsSignalMessage()
        {
            return envelope.Type == Envelope.Types.Type.Ciphertext;
        }

        /// <summary>
        /// True if the containing message is a <see cref="libsignal.protocol.PreKeySignalMessage"/>
        /// </summary>
        /// <returns>True if the containing message is a <see cref="libsignal.protocol.PreKeySignalMessage"/></returns>
        public bool IsPreKeySignalMessage()
        {
            return envelope.Type == Envelope.Types.Type.PrekeyBundle;
        }

        /// <summary>
        /// True if the containing message is a delivery receipt.
        /// </summary>
        /// <returns>True if the containing message is a delivery receipt.</returns>
        public bool IsReceipt()
        {
            return envelope.Type == Envelope.Types.Type.Receipt;
        }

        private byte[] GetPlaintext(byte[] ciphertext, byte[] cipherKey) //throws IOException
        {
            byte[] ivBytes = new byte[IV_LENGTH];
            System.Buffer.BlockCopy(ciphertext, IV_OFFSET, ivBytes, 0, ivBytes.Length);

            byte[] message = new byte[ciphertext.Length - VERSION_LENGTH - IV_LENGTH - MAC_SIZE];
            System.Buffer.BlockCopy(ciphertext, CIPHERTEXT_OFFSET, message, 0, message.Length);

            return Decrypt.aesCbcPkcs5(message, cipherKey, ivBytes);
        }

        private void VerifyMac(byte[] ciphertext, byte[] macKey)// throws IOException
        {
            if (ciphertext.Length < MAC_SIZE + 1)
                throw new Exception("Invalid MAC!");

            byte[] sign = new byte[ciphertext.Length - MAC_SIZE];
            Array.Copy(ciphertext, 0, sign, 0, ciphertext.Length - MAC_SIZE);

            byte[] ourMacFull = Sign.sha256sum(macKey, sign);
            byte[] ourMacBytes = new byte[MAC_SIZE];
            System.Buffer.BlockCopy(ourMacFull, 0, ourMacBytes, 0, ourMacBytes.Length);

            byte[] theirMacBytes = new byte[MAC_SIZE];
            System.Buffer.BlockCopy(ciphertext, ciphertext.Length - MAC_SIZE, theirMacBytes, 0, theirMacBytes.Length);

            /*Log.w(TAG, "Our MAC: " + Hex.toString(ourMacBytes));
            Log.w(TAG, "Thr MAC: " + Hex.toString(theirMacBytes));
            */
            if (!(ourMacBytes.SequenceEqual(theirMacBytes)))
            {
                throw new Exception("Invalid MAC compare!");
            }
        }

        private byte[] GetCipherKey(String signalingKey)// throws IOException
        {
            byte[] signalingKeyBytes = Base64.Decode(signalingKey);
            byte[] cipherKey = new byte[CIPHER_KEY_SIZE];
            System.Buffer.BlockCopy(signalingKeyBytes, 0, cipherKey, 0, cipherKey.Length);

            return cipherKey;
        }

        private byte[] GetMacKey(String signalingKey)// throws IOException
        {
            byte[] signalingKeyBytes = Base64.Decode(signalingKey);
            byte[] macKey = new byte[MAC_KEY_SIZE];
            System.Buffer.BlockCopy(signalingKeyBytes, CIPHER_KEY_SIZE, macKey, 0, macKey.Length);

            return macKey;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
