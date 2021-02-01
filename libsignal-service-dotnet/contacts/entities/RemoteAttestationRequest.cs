using Newtonsoft.Json;

namespace libsignalservice.contacts.entities
{
    public class RemoteAttestationRequest
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
