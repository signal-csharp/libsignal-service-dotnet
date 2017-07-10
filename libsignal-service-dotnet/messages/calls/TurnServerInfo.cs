using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libsignal_service_dotnet.messages.calls
{
    [JsonObject(MemberSerialization.OptIn)]
    public class TurnServerInfo
    {
        [JsonProperty("username", Required = Required.Always)]
        public string Username;

        [JsonProperty("password", Required = Required.Always)]
        public string Password;

        [JsonProperty("urls", Required = Required.Always)]
        public string[] Urls;
    }
}
