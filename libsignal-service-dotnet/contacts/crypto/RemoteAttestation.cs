using System.Collections.Generic;

namespace libsignalservice.contacts.crypto
{
    internal class RemoteAttestation
    {
        public byte[] RequestId { get; }
        public RemoteAttestationKeys Keys { get; }
        public IList<string> Cookies { get; }

        public RemoteAttestation(byte[] requestId, RemoteAttestationKeys keys, IList<string> cookies)
        {
            RequestId = requestId;
            Keys = keys;
            Cookies = cookies;
        }
    }
}
