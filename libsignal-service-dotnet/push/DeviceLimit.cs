using Newtonsoft.Json;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class DeviceLimit
    {
        [JsonProperty("current")]
        public int Current { get; set; }

        [JsonProperty("max")]
        public int Max { get; set; }
    }
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
}
