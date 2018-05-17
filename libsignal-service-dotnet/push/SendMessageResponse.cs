using Newtonsoft.Json;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SendMessageResponse
    {
        [JsonProperty("needsSync")]
        public bool NeedsSync { get; private set; }

        public SendMessageResponse() { }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
