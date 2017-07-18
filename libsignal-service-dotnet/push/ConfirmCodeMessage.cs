using Newtonsoft.Json;

namespace libsignal.push
{
    public class ConfirmCodeMessage
    {
        [JsonProperty]
        public string signalingKey { get; }

        [JsonProperty]
        public bool supportsSms { get; }

        [JsonProperty]
        public bool fetchesMessages { get; }

        [JsonProperty]
        public int registrationId { get; }

        [JsonProperty]
        public string name { get; }

        public ConfirmCodeMessage(string key, bool sms, bool fetches, int regId, string devicename)
        {
            signalingKey = key;
            supportsSms = sms;
            fetchesMessages = fetches;
            registrationId = regId;
            name = devicename;
        }
    }
}
