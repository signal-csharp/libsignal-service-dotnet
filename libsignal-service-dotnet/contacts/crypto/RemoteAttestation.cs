namespace libsignalservice.contacts.crypto
{
    public class RemoteAttestation
    {
        public byte[] RequestId { get; }
        public RemoteAttestationKeys Keys { get; }

        public RemoteAttestation(byte[] requestId, RemoteAttestationKeys keys)
        {
            RequestId = requestId;
            Keys = keys;
        }
    }
}
