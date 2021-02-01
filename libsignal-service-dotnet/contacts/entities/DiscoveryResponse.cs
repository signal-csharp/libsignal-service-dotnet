using Newtonsoft.Json;

namespace libsignalservice.contacts.entities
{
    public class DiscoveryResponse
    {
        [JsonProperty("iv")]
        public byte[]? Iv { get; }

        [JsonProperty("data")]
        public byte[]? Data { get; }

        [JsonProperty("mac")]
        public byte[]? Mac { get; }

        public DiscoveryResponse()
        {
        }

        public DiscoveryResponse(byte[] iv, byte[] data, byte[] mac)
        {
            Iv = iv;
            Data = data;
            Mac = mac;
        }

        public override string ToString()
        {
            return $"{{iv: {(Iv == null ? null : HelperMethods.ByteArrayToHexString(Iv))}, data: {(Data == null ? null : HelperMethods.ByteArrayToHexString(Data))}, mac: {(Mac == null ? null : HelperMethods.ByteArrayToHexString(Mac))}}}";
        }
    }
}
