using Newtonsoft.Json;

namespace libsignalservice.contacts.entities
{
    internal class RemoteAttestationResponse
    {
        [JsonProperty("serverEphemeralPublic")]
        public byte[] ServerEphemeralPublic { get; }

        [JsonProperty("serverStaticPublic")]
        public byte[] ServerStaticPublic { get; }

        [JsonProperty("quote")]
        public byte[] Quote { get; }

        [JsonProperty("iv")]
        public byte[] Iv { get; }

        [JsonProperty("ciphertext")]
        public byte[] Ciphertext { get; }

        [JsonProperty("tag")]
        public byte[] Tag { get; }

        [JsonProperty("signature")]
        public string Signature { get; }

        [JsonProperty("certificates")]
        public string Certificates { get; }

        [JsonProperty("signatureBody")]
        public string SignatureBody { get; }

        public RemoteAttestationResponse(byte[] serverEphemeralPublic, byte[] serverStaticPublic,
            byte[] iv, byte[] ciphertext, byte[] tag,
            byte[] quote, string signature, string certificates, string signatureBody)
        {
            ServerEphemeralPublic = serverEphemeralPublic;
            ServerStaticPublic = serverStaticPublic;
            Iv = iv;
            Ciphertext = ciphertext;
            Tag = tag;
            Quote = quote;
            Signature = signature;
            Certificates = certificates;
            SignatureBody = signatureBody;
        }
    }
}
