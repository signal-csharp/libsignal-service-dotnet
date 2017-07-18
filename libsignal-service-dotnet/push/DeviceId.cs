using Newtonsoft.Json;

namespace libsignal.push
{
    public class DeviceId
    {
        [JsonProperty]
        public int deviceId { get; set; }
    }
}
