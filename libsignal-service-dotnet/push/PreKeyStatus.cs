using Newtonsoft.Json;

namespace libsignalservice.push
{
    internal class PreKeyStatus
    {
        [JsonProperty("count")]
        public int Count { get; private set; }

        public PreKeyStatus() { }
    }
}
