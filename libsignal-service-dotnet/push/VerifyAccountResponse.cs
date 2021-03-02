using Newtonsoft.Json;

namespace libsignalservice.push
{
    internal class VerifyAccountResponse
    {
        [JsonProperty("uuid")]
        public string? Uuid { get; private set; }
    }
}
