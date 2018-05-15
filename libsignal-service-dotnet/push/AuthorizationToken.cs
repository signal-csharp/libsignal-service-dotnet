using Newtonsoft.Json;

namespace libsignalservice.push
{
    [JsonObject(MemberSerialization.OptIn)]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class AuthorizationToken
    {
        [JsonProperty("token", Required = Required.Always)]
        public string Token { get; set; }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
