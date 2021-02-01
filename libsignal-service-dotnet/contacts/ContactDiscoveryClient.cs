using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using libsignalservice.contacts.crypto;
using libsignalservice.contacts.entities;
using libsignalservice.push;
using org.whispersystems.curve25519;
using Org.BouncyCastle.Crypto;

namespace libsignalservice.contacts
{
    public class ContactDiscoveryClient
    {
        private readonly PushServiceSocket socket;

        public ContactDiscoveryClient(PushServiceSocket socket)
        {
            this.socket = socket;
        }

        public async Task<RemoteAttestation> GetRemoteAttestation(string mrenclave, CancellationToken? token)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            try
            {
                Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);
                Curve25519KeyPair keyPair = curve.generateKeyPair();

                ContactDiscoveryCipher cipher = new ContactDiscoveryCipher();
                RemoteAttestationRequest request = new RemoteAttestationRequest(keyPair.getPublicKey());
                RemoteAttestationResponse response = (await socket.GetContactDiscoveryRemoteAttestation("", request, mrenclave, token.Value)).Item1;

                RemoteAttestationKeys keys = new RemoteAttestationKeys(keyPair, response.ServerEphemeralPublic!, response.ServerStaticPublic!);
                Quote quote = new Quote(response.Quote!);
                byte[] requestId = cipher.GetRequestId(keys, response);

                cipher.VerifyServerQuote(quote, response.ServerStaticPublic!, mrenclave);
                cipher.VerifyIasSignature(response.Certificates!, response.SignatureBody!, response.Signature!, quote);

                return new RemoteAttestation(requestId, keys);
            }
            catch (InvalidCipherTextException ex)
            {
                throw new UnauthenticatedResponseException(ex);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="addressBook"></param>
        /// <param name="remoteAttestation"></param>
        /// <param name="mrenclave"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<IList<string>> GetRegisteredUsers(IList<string> addressBook, RemoteAttestation remoteAttestation, string mrenclave, CancellationToken? token)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            try
            {
                ContactDiscoveryCipher cipher = new ContactDiscoveryCipher();
                DiscoveryRequest request = cipher.CreateDiscoveryRequest(addressBook, remoteAttestation);
                DiscoveryResponse response = await socket.GetContactDiscoveryRegisteredUsers("", request, new List<string>(), mrenclave, token.Value);
                byte[] data = cipher.GetDiscoveryResponseData(response, remoteAttestation);

                IEnumerator<string> addressBookIterator = addressBook.GetEnumerator();
                List<string> results = new List<string>();

                foreach (byte aData in data)
                {
                    addressBookIterator.MoveNext();
                    string candidate = addressBookIterator.Current;

                    if (aData != 0)
                        results.Add(candidate);
                }

                return results;
            }
            catch (InvalidCipherTextException ex)
            {
                throw new IOException(null, ex);
            }
        }
    }
}
