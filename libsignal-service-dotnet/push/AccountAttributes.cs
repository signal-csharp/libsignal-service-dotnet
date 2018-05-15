using Newtonsoft.Json;

namespace libsignalservice.push
{
    [JsonObject(MemberSerialization.OptIn)]
    internal class AccountAttributes
    {
        [JsonProperty("signalingKey", Required = Required.Always)]
        private string SignalingKey { get; }

        [JsonProperty("registrationId", Required = Required.Always)]
        private uint RegistrationId { get; }

        [JsonProperty("voice", Required = Required.Always)]
        private bool Voice { get; }

        [JsonProperty("video", Required = Required.Always)]
        private bool Video { get; }

        [JsonProperty("fetchesMessages", Required = Required.Always)]
        private bool FetchesMessages { get; }

        [JsonProperty("pin")]
        private string Pin { get; }

        public AccountAttributes(string signalingKey, uint registrationId, bool fetchesMessages, string pin)
        {
            SignalingKey = signalingKey;
            RegistrationId = registrationId;
            Voice = true;
            Video = true;
            FetchesMessages = fetchesMessages;
            Pin = pin;
        }
    }
}
