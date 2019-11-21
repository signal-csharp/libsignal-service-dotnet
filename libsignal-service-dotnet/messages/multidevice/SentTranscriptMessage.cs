using System.Collections.Generic;
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
        public Dictionary<string, bool> UnidentifiedStatus { get; set; }

        public SentTranscriptMessage(string destination, long timestamp, SignalServiceDataMessage message,
            long expirationStartTimestamp, Dictionary<string, bool> unidentifiedStatus)
        {
            Destination = new May<string>(destination);
            Timestamp = timestamp;
            Message = message;
            ExpirationStartTimestamp = expirationStartTimestamp;
            UnidentifiedStatus = unidentifiedStatus;
        }

        public SentTranscriptMessage(long timestamp, SignalServiceDataMessage message)
        {
            Destination = May.NoValue;
            Timestamp = timestamp;
            Message = message;
            ExpirationStartTimestamp = 0;
            UnidentifiedStatus = new Dictionary<string, bool>();
        }

        public bool IsUnidentified(string destination)
        {
            if (UnidentifiedStatus.ContainsKey(destination))
            {
                return UnidentifiedStatus[destination];
            }
            return false;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
