using Newtonsoft.Json;
using System;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalServiceEnvelopeEntity
    {
        [JsonProperty("type")]
        public uint Type { get; set; }

        [JsonProperty("relay")]
        public string? Relay { get; set; }

        [JsonProperty("timestamp")]
        public ulong Timestamp { get; set; }

        [JsonProperty("source")]
        public string? Source { get; set; }

        [JsonProperty("sourceDevice")]
        public uint SourceDevice { get; set; }

        [JsonProperty("message")]
        public byte[]? Message { get; set; }

        [JsonProperty("content")]
        public byte[]? Content { get; set; }

        [JsonProperty("serverTimestamp")]
        public long ServerTimestamp { get; set; }

        [JsonProperty("guid")]
        public string? ServerUuid { get; set; }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
