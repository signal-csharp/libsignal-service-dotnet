using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.profiles
{
    public class SignalServiceProfile
    {
        [JsonProperty("identityKey")]
        public string IdentityKey { get; }
        [JsonProperty("name")]
        public string Name { get; }
        [JsonProperty("avatar")]
        public string Avatar { get; }
    }
}
