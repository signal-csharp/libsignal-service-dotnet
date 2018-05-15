using Newtonsoft.Json;
using System;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class DeviceInfo
    {
        [JsonProperty("id")]
        public long Id { get; private set; }

        [JsonProperty("name")]
        public String Name { get; private set; }

        [JsonProperty("created")]
        public long Created { get; private set; }

        [JsonProperty("lastSeen")]
        public long LastSeen { get; private set; }
    }
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
}
