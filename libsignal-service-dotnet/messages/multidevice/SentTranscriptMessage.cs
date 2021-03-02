using System;
using System.Collections.Generic;
using libsignalservice.push;

namespace libsignalservice.messages.multidevice
{
    public class SentTranscriptMessage
    {
        public SignalServiceAddress? Destination { get; }
        public long Timestamp { get; }
        public long ExpirationStartTimestamp { get; }
        public SignalServiceDataMessage Message { get; }
        public Dictionary<string, bool> UnidentifiedStatusByUuid { get; }
        public Dictionary<string, bool> UnidentifiedStatusByE164 { get; }
        public HashSet<SignalServiceAddress> Recipients { get; }
        public bool IsRecipientUpdate { get; }

        public SentTranscriptMessage(SignalServiceAddress destination, long timestamp, SignalServiceDataMessage message,
            long expirationStartTimestamp, Dictionary<SignalServiceAddress, bool> unidentifiedStatus,
            bool isRecipientUpdate)
        {
            Destination = destination;
            Timestamp = timestamp;
            Message = message;
            ExpirationStartTimestamp = expirationStartTimestamp;
            UnidentifiedStatusByUuid = new Dictionary<string, bool>();
            UnidentifiedStatusByE164 = new Dictionary<string, bool>();
            Recipients = new HashSet<SignalServiceAddress>(unidentifiedStatus.Keys);
            IsRecipientUpdate = isRecipientUpdate;

            foreach (var entry in unidentifiedStatus)
            {
                if (entry.Key.Uuid.HasValue)
                {
                    UnidentifiedStatusByUuid.Add(entry.Key.Uuid.Value.ToString(), entry.Value);
                }

                if (entry.Key.GetNumber() != null)
                {
                    UnidentifiedStatusByE164.Add(entry.Key.GetNumber()!, entry.Value);
                }
            }
        }

        public SentTranscriptMessage(long timestamp, SignalServiceDataMessage message)
        {
            Destination = null;
            Timestamp = timestamp;
            Message = message;
            ExpirationStartTimestamp = 0;
            UnidentifiedStatusByUuid = new Dictionary<string, bool>();
            UnidentifiedStatusByE164 = new Dictionary<string, bool>();
            Recipients = new HashSet<SignalServiceAddress>();
            IsRecipientUpdate = false;
        }

        public bool IsUnidentified(Guid uuid)
        {
            return IsUnidentified(uuid.ToString());
        }

        public bool IsUnidentified(string destination)
        {
            if (UnidentifiedStatusByUuid.ContainsKey(destination))
            {
                return UnidentifiedStatusByUuid[destination];
            }
            else if (UnidentifiedStatusByE164.ContainsKey(destination))
            {
                return UnidentifiedStatusByE164[destination];
            }
            else
            {
                return false;
            }
        }
    }
}
