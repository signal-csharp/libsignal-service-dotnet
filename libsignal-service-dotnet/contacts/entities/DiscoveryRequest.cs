using libsignalservice.util;
using Newtonsoft.Json;

namespace libsignalservice.contacts.entities
{
    public class DiscoveryRequest
    {
        [JsonProperty("addressCount")]
        public int AddressCount { get; }

        [JsonProperty("requestId")]
        public byte[]? RequestId { get; }

        [JsonProperty("iv")]
        public byte[]? Iv { get; }

        [JsonProperty("data")]
        public byte[]? Data { get; }

        [JsonProperty("mac")]
        public byte[]? Mac { get; }

        public DiscoveryRequest()
        {
        }

        public DiscoveryRequest(int addressCount, byte[] requestId, byte[] iv, byte[] data, byte[] mac)
        {
            AddressCount = addressCount;
            RequestId = requestId;
            Iv = iv;
            Data = data;
            Mac = mac;
        }

        public override string ToString()
        {
            return $"{{addressCount: {AddressCount}, ticket: {Hex.ToString(RequestId!)}, iv: {Hex.ToString(Iv!)}, data: {Hex.ToString(Data!)}, mac: {Hex.ToString(Mac!)}}}";
        }
    }
}
