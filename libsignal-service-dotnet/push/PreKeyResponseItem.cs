using Newtonsoft.Json;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    internal class PreKeyResponseItem
    {
        [JsonProperty("deviceId")]
        public uint DeviceId { get; set; }

        [JsonProperty("registrationId")]
        public uint RegistrationId { get; set; }

        [JsonProperty("signedPreKey")]
        public SignedPreKeyEntity SignedPreKey { get; set; }

        [JsonProperty("preKey")]
        public PreKeyEntity PreKey { get; set; }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
