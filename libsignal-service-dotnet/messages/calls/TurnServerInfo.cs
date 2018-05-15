using Newtonsoft.Json;

namespace libsignal_service_dotnet.messages.calls
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
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
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
