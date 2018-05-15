using Newtonsoft.Json;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class OutgoingPushMessage
    {
        [JsonProperty("type")]
        public uint OutgoingPushMessageType { get; set; }

        [JsonProperty("destinationDeviceId")]
        public uint DestinationDeviceId { get; set; }

        [JsonProperty("destinationRegistrationId")]
        public uint DestinationRegistrationId { get; set; }

        [JsonProperty("body")]
        public string Body { get; set; }

        [JsonProperty("content")]
        public string Content { get; set; }

        [JsonProperty("silent")]
        public bool Silent { get; set; }

        public OutgoingPushMessage(uint type,
                                   uint destinationDeviceId,
                                   uint destinationRegistrationId,
                                   string content,
                                   bool silent)
        {
            OutgoingPushMessageType = type;
            DestinationDeviceId = destinationDeviceId;
            DestinationRegistrationId = destinationRegistrationId;
            Content = content;
            Silent = silent;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
