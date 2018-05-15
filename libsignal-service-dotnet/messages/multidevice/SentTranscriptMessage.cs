using Strilanc.Value;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SentTranscriptMessage
    {
        public May<string> Destination { get; set; }
        public long Timestamp { get; set; }
        public long ExpirationStartTimestamp { get; set; }
        public SignalServiceDataMessage Message { get; set; }

        public SentTranscriptMessage(string destination, long timestamp, SignalServiceDataMessage message, long expirationStartTimestamp)
        {
            Destination = new May<string>(destination);
            Timestamp = timestamp;
            Message = message;
            ExpirationStartTimestamp = expirationStartTimestamp;
        }

        public SentTranscriptMessage(long timestamp, SignalServiceDataMessage message)
        {
            Destination = May.NoValue;
            Timestamp = timestamp;
            Message = message;
            ExpirationStartTimestamp = 0;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
