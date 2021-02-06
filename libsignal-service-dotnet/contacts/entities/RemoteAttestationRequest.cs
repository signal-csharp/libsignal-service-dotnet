using Newtonsoft.Json;

namespace libsignalservice.contacts.entities
{
    internal class RemoteAttestationRequest
    {
        [JsonProperty("clientPublic")]
        public byte[]? ClientPublic { get; }

        public RemoteAttestationRequest()
        {
        }

        public RemoteAttestationRequest(byte[] clientPublic)
        {
            ClientPublic = clientPublic;
        }
    }
}
