using Newtonsoft.Json;

namespace libsignal.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class ConfirmCodeMessage
    {
        [JsonProperty("signalingKey")]
        public string SignalingKey { get; }

        [JsonProperty("supportsSms")]
        public bool SupportsSms { get; }

        [JsonProperty("fetchesMessages")]
        public bool FetchesMessages { get; }

        [JsonProperty("registrationId")]
        public int RegistrationId { get; }

        [JsonProperty("name")]
        public string Name { get; }

        public ConfirmCodeMessage(string key, bool sms, bool fetches, int regId, string devicename)
        {
            SignalingKey = key;
            SupportsSms = sms;
            FetchesMessages = fetches;
            RegistrationId = regId;
            Name = devicename;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
