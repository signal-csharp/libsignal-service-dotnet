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
        public string IdentityKey { get; set; }
        [JsonProperty("name")]
        public string Name { get; set; }
        [JsonProperty("avatar")]
        public string Avatar { get; set; }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
