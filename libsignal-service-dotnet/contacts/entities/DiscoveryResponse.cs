using libsignalservice.util;
using Newtonsoft.Json;

namespace libsignalservice.contacts.entities
{
    internal class DiscoveryResponse
    {
        [JsonProperty("requestId")]
        public byte[]? RequestId { get; }

        [JsonProperty("iv")]
        public byte[]? Iv { get; }

        [JsonProperty("data")]
        public byte[]? Data { get; }

        [JsonProperty("mac")]
        public byte[]? Mac { get; }

        public override string ToString()
        {
            return $"{{iv: {(Iv == null ? null : Hex.ToString(Iv))}, data: {(Data == null ? null : Hex.ToString(Data))}, mac: {(Mac == null ? null : Hex.ToString(Mac))}}}";
        }
    }
}
