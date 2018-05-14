using Newtonsoft.Json;

namespace libsignal.push
{
    internal class DeviceId
    {
        [JsonProperty("deviceId")]
        public int NewDeviceId { get; set; }
    }
}
