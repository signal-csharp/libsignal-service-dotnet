using Newtonsoft.Json;

namespace libsignalservice.push
{
    [JsonObject(MemberSerialization.OptIn)]
    internal class AccountAttributes
    {
        [JsonProperty("signalingKey", Required = Required.Always)]
        public string SignalingKey { get; }

        [JsonProperty("registrationId", Required = Required.Always)]
        public uint RegistrationId { get; }

        [JsonProperty("voice", Required = Required.Always)]
        public bool Voice { get; }

        [JsonProperty("video", Required = Required.Always)]
        public bool Video { get; }

        [JsonProperty("fetchesMessages", Required = Required.Always)]
        public bool FetchesMessages { get; }

        [JsonProperty("pin")]
        public string Pin { get; }

        [JsonProperty("unidentifiedAccessKey")]
        public byte[] UnidentifiedAccessKey { get; }

        [JsonProperty("unrestrictedUnidentifiedAccess")]
        public bool UnrestrictedUnidentifiedAccess { get; }

        public AccountAttributes(string signalingKey, uint registrationId, bool fetchesMessages, string pin,
             byte[] unidentifiedAccessKey, bool unrestrictedUnidentifiedAccess)
        {
            SignalingKey = signalingKey;
            RegistrationId = registrationId;
            Voice = true;
            Video = true;
            FetchesMessages = fetchesMessages;
            Pin = pin;
            UnidentifiedAccessKey = unidentifiedAccessKey;
            UnrestrictedUnidentifiedAccess = unrestrictedUnidentifiedAccess;
        }
    }
}
