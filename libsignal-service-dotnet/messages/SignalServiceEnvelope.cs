using System;
using Google.Protobuf;
using libsignalservice.push;
using libsignalservice.util;
using static libsignalservice.SignalServiceMessagePipe;

namespace libsignalservice.messages
{
    /// <summary>
    /// This class represents an encrypted Signal Service envelope.
    ///
    /// The envelope contains the wrapping information, such as the sender, the
    /// message timestamp, the encrypted message type, etc.
    /// </summary>
    public class SignalServiceEnvelope: SignalServiceMessagePipeMessage
    {
        public Envelope Envelope { get; }

        /// <summary>
        /// Construct an envelope from a serialized, Base64 encoded SignalServiceEnvelope.
        /// </summary>
        /// <param name="message">The serialized SignalServiceEnvelope, base64 encoded and encrypted.</param>
        public SignalServiceEnvelope(string message)
            : this(Base64.Decode(message))
        {
        }

        /// <summary>
        /// Construct an envelope from a serialized SignalServiceEnvelope.
        /// </summary>
        /// <param name="input">The serialized and (optionally) encrypted SignalServiceEnvelope.</param>
        public SignalServiceEnvelope(byte[] input)
        {
            Envelope = Envelope.Parser.ParseFrom(input);
        }

        public SignalServiceEnvelope(int type, string sender, int senderDevice,
            long timestamp, byte[] legacyMessage, byte[] content, long serverTimestamp, string? uuid)
        {
            Envelope envelope = new Envelope
            {
                Type = (Envelope.Types.Type)type,
                Source = sender,
                SourceDevice = (uint)senderDevice,
                Timestamp = (ulong)timestamp,
                ServerTimestamp = (ulong) serverTimestamp
            };

            if (uuid != null) envelope.ServerGuid = uuid;
            if (legacyMessage != null) envelope.LegacyMessage = ByteString.CopyFrom(legacyMessage);
            if (content != null) envelope.Content = ByteString.CopyFrom(content);

            Envelope = envelope;
        }

        public SignalServiceEnvelope(int type, long timestamp, byte[] legacyMessage, byte[] content, long serverTimestamp, String uuid)
        {
            Envelope envelope = new Envelope
            {
                Type = (Envelope.Types.Type)type,
                Timestamp = (ulong)timestamp,
                ServerTimestamp = (ulong)serverTimestamp
            };

            if (uuid != null) envelope.ServerGuid = uuid;
            if (legacyMessage != null) envelope.LegacyMessage = ByteString.CopyFrom(legacyMessage);
            if (content != null) envelope.Content = ByteString.CopyFrom(content);

            Envelope = envelope;
        }

        /// <summary>
        /// The envelope's sender.
        /// </summary>
        /// <returns>The envelope's sender.</returns>
        public string GetSource()
        {
            return Envelope.Source;
        }

        /// <summary>
        /// The envelope's sender device ID.
        /// </summary>
        /// <returns>The envelope's sender device ID.</returns>
        public int GetSourceDevice()
        {
            return (int)Envelope.SourceDevice;
        }

        /// <summary>
        /// The envelope's sender as a SignalServiceAddress.
        /// </summary>
        /// <returns>The envelope's sender as a SignalServiceAddress.</returns>
        public SignalServiceAddress GetSourceAddress()
        {
            return new SignalServiceAddress(Envelope.Source);
        }

        /// <summary>
        /// The envelope content type.
        /// </summary>
        /// <returns>The envelope content type.</returns>
        public int GetEnvelopeType()
        {
            return (int)Envelope.Type;
        }

        /// <summary>
        /// The timestamp this envelope was sent.
        /// </summary>
        /// <returns>The timestamp this envelope was sent.</returns>
        public long GetTimestamp()
        {
            return (long)Envelope.Timestamp;
        }

        /// <summary>
        /// Whether the envelope contains a SignalServiceDataMessage
        /// </summary>
        /// <returns>Whether the envelope contains a SignalServiceDataMessage</returns>
        public bool HasLegacyMessage()
        {
            return Envelope.LegacyMessageOneofCase == Envelope.LegacyMessageOneofOneofCase.LegacyMessage;
        }

        /// <summary>
        /// The envelope's containing SignalService message.
        /// </summary>
        /// <returns>The envelope's containing SignalService message.</returns>
        public byte[] GetLegacyMessage()
        {
            return Envelope.LegacyMessage.ToByteArray();
        }

        /// <summary>
        /// Whether the envelope contains an encrypted SignalServiceContent
        /// </summary>
        /// <returns>Whether the envelope contains an encrypted SignalServiceContent</returns>
        public bool HasContent()
        {
            return Envelope.ContentOneofCase == Envelope.ContentOneofOneofCase.Content;
        }

        /// <summary>
        /// The envelope's containing message.
        /// </summary>
        /// <returns>The envelope's containing message.</returns>
        public byte[] GetContent()
        {
            return Envelope.Content.ToByteArray();
        }

        /// <summary>
        /// True if the containing message is a <see cref="libsignal.protocol.SignalMessage"/>
        /// </summary>
        /// <returns>True if the containing message is a <see cref="libsignal.protocol.SignalMessage"/></returns>
        public bool IsSignalMessage()
        {
            return Envelope.Type == Envelope.Types.Type.Ciphertext;
        }

        /// <summary>
        /// True if the containing message is a <see cref="libsignal.protocol.PreKeySignalMessage"/>
        /// </summary>
        /// <returns>True if the containing message is a <see cref="libsignal.protocol.PreKeySignalMessage"/></returns>
        public bool IsPreKeySignalMessage()
        {
            return Envelope.Type == Envelope.Types.Type.PrekeyBundle;
        }

        /// <summary>
        /// True if the containing message is a delivery receipt.
        /// </summary>
        /// <returns>True if the containing message is a delivery receipt.</returns>
        public bool IsReceipt()
        {
            return Envelope.Type == Envelope.Types.Type.Receipt;
        }

        public bool IsUnidentifiedSender()
        {
            return Envelope.Type == Envelope.Types.Type.UnidentifiedSender;
        }
    }
}
