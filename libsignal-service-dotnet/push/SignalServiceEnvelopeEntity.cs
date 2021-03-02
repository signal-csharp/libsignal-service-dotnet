using Newtonsoft.Json;

namespace libsignalservice.push
{
    public class SignalServiceEnvelopeEntity
    {
        [JsonProperty("type")]
        public uint Type { get; private set; }

        [JsonProperty("relay")]
        public string? Relay { get; private set; }

        [JsonProperty("timestamp")]
        public ulong Timestamp { get; private set; }

        [JsonProperty("source")]
        public string? SourceE164 { get; private set; }

        [JsonProperty("sourceUuid")]
        public string? SourceUuid { get; private set; }

        [JsonProperty("sourceDevice")]
        public uint SourceDevice { get; private set; }

        [JsonProperty("message")]
        public byte[]? Message { get; private set; }

        [JsonProperty("content")]
        public byte[]? Content { get; private set; }

        [JsonProperty("serverTimestamp")]
        public long ServerTimestamp { get; private set; }

        [JsonProperty("guid")]
        public string? ServerUuid { get; private set; }

        public bool HasSource()
        {
            return SourceE164 != null || SourceUuid != null;
        }
    }
}
