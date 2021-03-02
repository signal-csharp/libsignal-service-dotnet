using Newtonsoft.Json;

namespace libsignalservice.push
{
    public class AttachmentV2UploadAttributes
    {
        [JsonProperty("url")]
        public string? Url { get; private set; }

        [JsonProperty("key")]
        public string? Key { get; private set; }

        [JsonProperty("credential")]
        public string? Credential { get; private set; }

        [JsonProperty("acl")]
        public string? Acl { get; private set; }

        [JsonProperty("algorithm")]
        public string? Algorithm { get; private set; }

        [JsonProperty("date")]
        public string? Date { get; private set; }

        [JsonProperty("policy")]
        public string? Policy { get; private set; }

        [JsonProperty("signature")]
        public string? Signature { get; private set; }

        [JsonProperty("attachmentId")]
        public string? AttachmentId { get; private set; }

        [JsonProperty("attachmentIdString")]
        public string? AttachmentIdString { get; private set; }
    }
}
