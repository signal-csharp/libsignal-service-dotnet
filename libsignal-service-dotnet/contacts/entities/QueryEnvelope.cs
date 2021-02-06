using Newtonsoft.Json;

namespace libsignalservice.contacts.entities
{
    internal class QueryEnvelope
    {
        [JsonProperty("requestId")]
        public byte[] RequestId { get; }

        [JsonProperty("iv")]
        public byte[] Iv { get; }
        
        [JsonProperty("data")]
        public byte[] Data { get; }

        [JsonProperty("mac")]
        public byte[] Mac { get; }

        public QueryEnvelope(byte[] requestId, byte[] iv, byte[] data, byte[] mac)
        {
            RequestId = requestId;
            Iv = iv;
            Data = data;
            Mac = mac;
        }
    }
}
