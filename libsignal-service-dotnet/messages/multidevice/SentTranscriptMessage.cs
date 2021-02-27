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
        public bool IsRecipientUpdate { get; }

        public SentTranscriptMessage(string destination, long timestamp, SignalServiceDataMessage message,
            long expirationStartTimestamp, Dictionary<string, bool> unidentifiedStatus,
            bool isRecipientUpdate)
        {
            Destination = destination;
            Timestamp = timestamp;
            Message = message;
            ExpirationStartTimestamp = expirationStartTimestamp;
            UnidentifiedStatus = unidentifiedStatus;
            IsRecipientUpdate = isRecipientUpdate;
        }

        public SentTranscriptMessage(long timestamp, SignalServiceDataMessage message)
        {
            Destination = null;
            Timestamp = timestamp;
            Message = message;
            ExpirationStartTimestamp = 0;
            UnidentifiedStatus = new Dictionary<string, bool>();
            IsRecipientUpdate = false;
        }

        public bool IsUnidentified(string destination)
        {
            if (UnidentifiedStatus.ContainsKey(destination))
            {
                return UnidentifiedStatus[destination];
            }
            return false;
        }

        public HashSet<string> GetRecipients()
        {
            return new HashSet<string>(UnidentifiedStatus.Keys);
        }
    }
}
