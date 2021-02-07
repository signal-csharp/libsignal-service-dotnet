using System.Collections.Generic;
using Newtonsoft.Json;

namespace libsignalservice.contacts.entities
{
    internal class MultiRemoteAttestationResponse
    {
        [JsonProperty("attestations")]
        public Dictionary<string, RemoteAttestationResponse>? Attestations { get; private set; }
    }
}
