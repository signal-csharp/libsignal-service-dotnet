using Newtonsoft.Json;
using System;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    [JsonObject(MemberSerialization.OptIn)]
    public class ContactTokenDetails
    {
        [JsonProperty("token")]
        public string Token { get; set; }

        [JsonProperty("relay")]
        public string Relay { get; set; }

        [JsonProperty("number")]
        public string Number { get; set; }

        [JsonProperty("voice")]
        public bool Voice { get; set; }

        [JsonProperty("video")]
        public bool Video { get; set; }
    }
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
}
