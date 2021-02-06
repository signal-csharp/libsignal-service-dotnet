using Newtonsoft.Json;

namespace libsignalservice.push
{
    internal class ContactDiscoveryCredentials
    {
        [JsonProperty("username")]
        public string? Username { get; set; }

        [JsonProperty("password")]
        public string? Password { get; set; }
    }
}
