using Newtonsoft.Json;

namespace libsignalservice.push
{
    internal class ContactDiscoveryCredentials
    {
        [JsonProperty("username")]
        public string? Username { get; private set; }

        [JsonProperty("password")]
        public string? Password { get; private set; }
    }
}
