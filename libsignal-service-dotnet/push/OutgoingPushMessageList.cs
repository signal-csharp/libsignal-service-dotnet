using System.Collections.Generic;
using Newtonsoft.Json;

namespace libsignalservice.push
{
    public class OutgoingPushMessageList
    {
        [JsonProperty("destination")]
        public string Destination { get; }

        [JsonProperty("timestamp")]
        public ulong Timestamp { get; }

        [JsonProperty("messages")]
        public List<OutgoingPushMessage> Messages { get; }

        [JsonProperty("online")]
        public bool Online { get; }

        public OutgoingPushMessageList(string destination,
            ulong timestamp,
            List<OutgoingPushMessage> messages,
            bool online)
        {
            Timestamp = timestamp;
            Destination = destination;
            Messages = messages;
            Online = online;
        }
    }
}
