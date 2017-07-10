using Google.Protobuf;
using libsignal;
using libsignal.util;
using libsignalservice.push;
using libsignalservice.util;
using Strilanc.Value;

/**
 * Copyright (C) 2017 smndtrl, golf1052
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
using System.Linq;

namespace libsignalservice.messages
{
    /// <summary>
    /// This class represents an encrypted Signal Service envelope.
    ///
    /// The envelope contains the wrapping information, such as the sender, the
    /// message timestamp, the encrypted message type, etc.
    /// </summary>
    public class SignalServiceEnvelope
    {
        private static readonly string TAG = "SignalServiceEnvelope";

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

        /**
         * Construct an envelope from a serialized, Base64 encoded TextSecureEnvelope, encrypted
         * with a signaling key.
         *
         * @param message The serialized TextSecureEnvelope, base64 encoded and encrypted.
         * @param signalingKey The signaling key.
         * @throws IOException
         * @throws InvalidVersionException
         */

        public SignalServiceEnvelope(String message, String signalingKey)
            : this(Base64.decode(message), signalingKey)
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

            byte[] cipherKey = getCipherKey(signalingKey);
            byte[] macKey = getMacKey(signalingKey);

            verifyMac(ciphertext, macKey);

            envelope = Envelope.Parser.ParseFrom(getPlaintext(ciphertext, cipherKey));
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
        public string getSource()
        {
            return envelope.Source;
        }

        /// <summary>
        /// The envelope's sender device ID.
        /// </summary>
        /// <returns>The envelope's sender device ID.</returns>
        public int getSourceDevice()
        {
            return (int)envelope.SourceDevice;
        }

        /// <summary>
        /// The envelope's sender as a SignalServiceAddress.
        /// </summary>
        /// <returns>The envelope's sender as a SignalServiceAddress.</returns>
        public SignalServiceAddress getSourceAddress()
        {
            return new SignalServiceAddress(envelope.Source,
                                         envelope.RelayOneofCase == Envelope.RelayOneofOneofCase.Relay ? new May<string>(envelope.Relay) :
                                                             May<string>.NoValue);
        }

        /// <summary>
        /// The envelope content type.
        /// </summary>
        /// <returns>The envelope content type.</returns>
        public int getType()
        {
            return (int)envelope.Type;
        }

        /// <summary>
        /// The federated server this envelope came from.
        /// </summary>
        /// <returns>The federated server this envelope came from.</returns>
        public string getRelay()
        {
            return envelope.Relay;
        }

        /// <summary>
        /// The timestamp this envelope was sent.
        /// </summary>
        /// <returns>The timestamp this envelope was sent.</returns>
        public long getTimestamp()
        {
            return (long)envelope.Timestamp;
        }

        /// <summary>
        /// Whether the envelope contains a SignalServiceDataMessage
        /// </summary>
        /// <returns>Whether the envelope contains a SignalServiceDataMessage</returns>
        public bool hasLegacyMessage()
        {
            return envelope.LegacyMessageOneofCase == Envelope.LegacyMessageOneofOneofCase.LegacyMessage;
        }

        /// <summary>
        /// The envelope's containing SignalService message.
        /// </summary>
        /// <returns>The envelope's containing SignalService message.</returns>
        public byte[] getLegacyMessage()
        {
            return envelope.LegacyMessage.ToByteArray();
        }

        /// <summary>
        /// Whether the envelope contains an encrypted SignalServiceContent
        /// </summary>
        /// <returns>Whether the envelope contains an encrypted SignalServiceContent</returns>
        public bool hasContent()
        {
            return envelope.ContentOneofCase == Envelope.ContentOneofOneofCase.Content;
        }

        /// <summary>
        /// The envelope's containing message.
        /// </summary>
        /// <returns>The envelope's containing message.</returns>
        public byte[] getContent()
        {
            return envelope.Content.ToByteArray();
        }

        /// <summary>
        /// True if the containing message is a <see cref="libsignal.protocol.SignalMessage"/>
        /// </summary>
        /// <returns>True if the containing message is a <see cref="libsignal.protocol.SignalMessage"/></returns>
        public bool isSignalMessage()
        {
            return envelope.Type == Envelope.Types.Type.Ciphertext;
        }

        /// <summary>
        /// True if the containing message is a <see cref="libsignal.protocol.PreKeySignalMessage"/>
        /// </summary>
        /// <returns>True if the containing message is a <see cref="libsignal.protocol.PreKeySignalMessage"/></returns>
        public bool isPreKeySignalMessage()
        {
            return envelope.Type == Envelope.Types.Type.PrekeyBundle;
        }

        /// <summary>
        /// True if the containing message is a delivery receipt.
        /// </summary>
        /// <returns>True if the containing message is a delivery receipt.</returns>
        public bool isReceipt()
        {
            return envelope.Type == Envelope.Types.Type.Receipt;
        }

        private byte[] getPlaintext(byte[] ciphertext, byte[] cipherKey) //throws IOException
        {
            byte[] ivBytes = new byte[IV_LENGTH];
            System.Buffer.BlockCopy(ciphertext, IV_OFFSET, ivBytes, 0, ivBytes.Length);

            byte[] message = new byte[ciphertext.Length - VERSION_LENGTH - IV_LENGTH - MAC_SIZE];
            System.Buffer.BlockCopy(ciphertext, CIPHERTEXT_OFFSET, message, 0, message.Length);

            return Decrypt.aesCbcPkcs5(message, cipherKey, ivBytes);
        }

        private void verifyMac(byte[] ciphertext, byte[] macKey)// throws IOException
        {
            try
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
            catch (InvalidKeyException e) { }
        }

        private byte[] getCipherKey(String signalingKey)// throws IOException
        {
            byte[] signalingKeyBytes = Base64.decode(signalingKey);
            byte[] cipherKey = new byte[CIPHER_KEY_SIZE];
            System.Buffer.BlockCopy(signalingKeyBytes, 0, cipherKey, 0, cipherKey.Length);

            return cipherKey;
        }

        private byte[] getMacKey(String signalingKey)// throws IOException
        {
            byte[] signalingKeyBytes = Base64.decode(signalingKey);
            byte[] macKey = new byte[MAC_KEY_SIZE];
            System.Buffer.BlockCopy(signalingKeyBytes, CIPHER_KEY_SIZE, macKey, 0, macKey.Length);

            return macKey;
        }
    }
}
