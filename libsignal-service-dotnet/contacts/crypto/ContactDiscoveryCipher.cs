using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using libsignal.util;
using libsignalservice.contacts.entities;
using libsignalservice.crypto;
using libsignalservice.util;

namespace libsignalservice.contacts.crypto
{
    internal static class ContactDiscoveryCipher
    {
        public static DiscoveryRequest CreateDiscoveryRequest(IList<string> addressBook, Dictionary<string, RemoteAttestation> remoteAttestations)
        {
            byte[] queryDataKey = Util.GetSecretBytes(32);
            byte[] queryData = BuildQueryData(addressBook);
            AesCipher.AesEncryptedResult encryptedQueryData = AesCipher.Encrypt(queryDataKey, null, queryData);
            byte[] commitment = CryptoUtil.Sha256(queryData);
            Dictionary<string, QueryEnvelope> envelopes = new Dictionary<string, QueryEnvelope>(remoteAttestations.Count);

            foreach (var entry in remoteAttestations)
            {
                envelopes.Add(entry.Key,
                    BuildQueryEnvelope(entry.Value.RequestId, entry.Value.Keys.ClientKey, queryDataKey));
            }

            return new DiscoveryRequest(addressBook.Count,
                commitment,
                encryptedQueryData.iv,
                encryptedQueryData.data,
                encryptedQueryData.mac,
                envelopes);
        }

        public static byte[] GetDiscoveryResponseData(DiscoveryResponse response, ICollection<RemoteAttestation> attestations)
        {
            foreach (RemoteAttestation attestation in attestations)
            {
                if (Enumerable.SequenceEqual(response.RequestId, attestation.RequestId))
                {
                    return AesCipher.Decrypt(attestation.Keys.ServerKey, response.Iv!, response.Data!, response.Mac!);
                }
            }
            throw new NoMatchingRequestIdException();
        }

        private static byte[] BuildQueryData(IList<string> addresses)
        {
            try
            {
                byte[] nonce = Util.GetSecretBytes(32);
                MemoryStream requestDataStream = new MemoryStream();
                requestDataStream.Write(nonce, 0, nonce.Length);
                foreach (string address in addresses)
                {
                    byte[] arr = ByteUtil.longToByteArray(long.Parse(address));
                    requestDataStream.Write(arr, 0, arr.Length);
                }

                return requestDataStream.ToArray();
            }
            catch (IOException ex)
            {
                throw new InvalidOperationException(null, ex);
            }
        }

        private static QueryEnvelope BuildQueryEnvelope(byte[] requestId, byte[] clientKey, byte[] queryDataKey)
        {
            AesCipher.AesEncryptedResult result = AesCipher.Encrypt(clientKey, requestId, queryDataKey);
            return new QueryEnvelope(requestId, result.iv, result.data, result.mac);
        }

        public class NoMatchingRequestIdException : IOException
        {
        }
    }
}
