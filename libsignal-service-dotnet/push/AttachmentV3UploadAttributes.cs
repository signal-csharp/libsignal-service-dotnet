using System.Collections.Generic;
using Newtonsoft.Json;

namespace libsignalservice.push
{
    internal class AttachmentV3UploadAttributes
    {
        [JsonProperty("cdn")]
        public int Cdn { get; private set; }

        [JsonProperty("key")]
        public string? Key { get; private set; }

        [JsonProperty("headers")]
        public Dictionary<string, string>? Headers { get; private set; }

        [JsonProperty("signedUploadLocation")]
        public string? SignedUploadLocation { get; private set; }
    }
}
