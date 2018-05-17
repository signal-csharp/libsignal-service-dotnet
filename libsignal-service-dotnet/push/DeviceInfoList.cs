using libsignalservice.messages.multidevice;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace libsignalservice.push
{
    internal class DeviceInfoList
    {
        [JsonProperty("devices")]
        public List<DeviceInfo> Devices { get; private set; }
        public DeviceInfoList() { }
    }
}
