using System.Collections.Generic;

namespace libsignalservice.messages.multidevice
{
    public class SentTranscriptMessage
    {
        public string? Destination { get; }
        public long Timestamp { get; }
        public long ExpirationStartTimestamp { get; }
        public SignalServiceDataMessage Message { get; }
        public Dictionary<string, bool> UnidentifiedStatus { get; }

        public SentTranscriptMessage(string destination, long timestamp, SignalServiceDataMessage message,
            long expirationStartTimestamp, Dictionary<string, bool> unidentifiedStatus)
        {
            Destination = destination;
            Timestamp = timestamp;
            Message = message;
            ExpirationStartTimestamp = expirationStartTimestamp;
            UnidentifiedStatus = unidentifiedStatus;
        }

        public SentTranscriptMessage(long timestamp, SignalServiceDataMessage message)
        {
            Destination = null;
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
}
