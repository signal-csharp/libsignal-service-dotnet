using Newtonsoft.Json;

namespace libsignalservice.push
{
    internal class WhoAmIResponse
    {
        [JsonProperty("uuid")]
        public string? Uuid { get; private set; }
    }
}
