using libsignal;
using Newtonsoft.Json;

using System.Collections.Generic;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    [JsonObject(MemberSerialization.OptIn)]
    public class PreKeyState
    {
        [JsonProperty(Required = Required.Always, Order = 1)]
        [JsonConverter(typeof(IdentityKeySerializer))]
        private IdentityKey identityKey;

        [JsonProperty(Required = Required.Always, Order = 2)]
        private List<PreKeyEntity> preKeys;

        [JsonProperty(Required = Required.Always, Order = 3)]
        private SignedPreKeyEntity signedPreKey;

        public PreKeyState(List<PreKeyEntity> preKeys, SignedPreKeyEntity signedPreKey, IdentityKey identityKey)
        {
            this.preKeys = preKeys;
            this.signedPreKey = signedPreKey;
            this.identityKey = identityKey;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
