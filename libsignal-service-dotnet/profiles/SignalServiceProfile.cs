using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.profiles
{
    public class SignalServiceProfile
    {
        [JsonProperty("identityKey")]
        public string? IdentityKey { get; private set; }

        [JsonProperty("name")]
        public string? Name { get; private set; }

        [JsonProperty("avatar")]
        public string? Avatar { get; private set; }

        [JsonProperty("unidentifiedAccess")]
        public string? UnidentifiedAccess { get; private set; }

        [JsonProperty("unrestrictedUnidentifiedAccess")]
        public bool UnrestrictedUnidentifiedAccess { get; private set; }

        [JsonProperty("capabilities")]
        public Capabilities? _Capabilities { get; private set; }

        public class Capabilities
        {
            [JsonProperty("uuid")]
            public bool Uuid { get; private set; }
        }
    }
}
