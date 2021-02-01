using Newtonsoft.Json;

namespace libsignalservice.contacts.crypto
{
    internal class SignatureBodyEntity
    {
        [JsonProperty("isvEnclaveQuoteBody")]
        public byte[]? IsvEnclaveQuoteBody { get; }

        [JsonProperty("isvEnclaveQuoteStatus")]
        public string? IsvEnclaveQuoteStatus { get; }

        [JsonProperty("version")]
        public long Version { get; }

        [JsonProperty("timestamp")]
        public string? Timestamp { get; }
    }
}
