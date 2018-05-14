using Newtonsoft.Json;
using System.Collections.Generic;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    [JsonObject(MemberSerialization.OptIn)]
    public class MismatchedDevices
    {
        [JsonProperty("missingDevices")]
        public List<int> MissingDevices { get; set; }

        [JsonProperty("extraDevices")]
        public List<int> ExtraDevices { get; set; }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
