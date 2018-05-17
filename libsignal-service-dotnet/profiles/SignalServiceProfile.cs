using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.profiles
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalServiceProfile
    {
        [JsonProperty("identityKey")]
        public string IdentityKey { get; private set; }
        [JsonProperty("name")]
        public string Name { get; private set; }
        [JsonProperty("avatar")]
        public string Avatar { get; private set; }

        public SignalServiceProfile() { }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
