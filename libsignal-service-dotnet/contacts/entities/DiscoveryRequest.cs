using System.Collections.Generic;
using Newtonsoft.Json;

namespace libsignalservice.contacts.entities
{
    internal class DiscoveryRequest
    {
        [JsonProperty("addressCount")]
        public int AddressCount { get; }

        [JsonProperty("commitment")]
        public byte[] Commitment { get; }

        [JsonProperty("iv")]
        public byte[]? Iv { get; }

        [JsonProperty("data")]
        public byte[]? Data { get; }

        [JsonProperty("mac")]
        public byte[]? Mac { get; }

        [JsonProperty("envelopes")]
        public Dictionary<string, QueryEnvelope> Envelopes;

        public DiscoveryRequest(int addressCount, byte[] commitment, byte[] iv, byte[] data, byte[] mac, Dictionary<string, QueryEnvelope> envelopes)
        {
            AddressCount = addressCount;
            Commitment = commitment;
            Iv = iv;
            Data = data;
            Mac = mac;
            Envelopes = envelopes;
        }

        public override string ToString()
        {
            return $"{{ addressCount: {AddressCount}, envelopes: {Envelopes.Count} }}";
        }
    }
}
