using Newtonsoft.Json;

namespace libsignalservice.contacts.crypto
{
    internal class SignatureBodyEntity
    {
        [JsonProperty("isvEnclaveQuoteBody")]
        public byte[]? IsvEnclaveQuoteBody { get; private set; }

        [JsonProperty("isvEnclaveQuoteStatus")]
        public string? IsvEnclaveQuoteStatus { get; private set; }

        [JsonProperty("version")]
        public long Version { get; private set; }

        [JsonProperty("timestamp")]
        public string? Timestamp { get; private set; }
    }
}
