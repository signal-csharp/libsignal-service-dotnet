using Newtonsoft.Json;
using System;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    [JsonObject(MemberSerialization.OptIn)]
    public class ContactTokenDetails
    {
        [JsonProperty("token")]
        public string Token { get; private set; }

        [JsonProperty("relay")]
        public string Relay { get; private set; }

        [JsonProperty("number")]
        public string Number { get; set; }

        [JsonProperty("voice")]
        public bool Voice { get; private set; }

        [JsonProperty("video")]
        public bool Video { get; private set; }

        public ContactTokenDetails() { }
    }
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
}
