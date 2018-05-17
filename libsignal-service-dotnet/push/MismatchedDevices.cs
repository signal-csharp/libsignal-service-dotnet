using Newtonsoft.Json;
using System.Collections.Generic;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    [JsonObject(MemberSerialization.OptIn)]
    public class MismatchedDevices
    {
        [JsonProperty("missingDevices")]
        public List<int> MissingDevices { get; private set; }

        [JsonProperty("extraDevices")]
        public List<int> ExtraDevices { get; private set; }

        public MismatchedDevices() { }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
