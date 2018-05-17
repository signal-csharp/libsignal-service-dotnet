using Newtonsoft.Json;
using System.Collections.Generic;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class StaleDevices
    {
        [JsonProperty("staleDevices")]
        public List<int> Devices { get; private set; }

        public StaleDevices() { }
    }
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
}
