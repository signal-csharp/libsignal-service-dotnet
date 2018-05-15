using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class OutgoingPushMessageList
    {
        [JsonProperty("destination")]
        public String Destination { get; set; }

        [JsonProperty("relay")]
        public String Relay { get; set; }

        [JsonProperty("timestamp")]
        public ulong Timestamp { get; set; }

        [JsonProperty("messages")]
        public List<OutgoingPushMessage> Messages { get; set; }

        public OutgoingPushMessageList(String destination, ulong timestamp, String relay,
                                       List<OutgoingPushMessage> messages)
        {
            Timestamp = timestamp;
            Destination = destination;
            Relay = relay;
            Messages = messages;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
