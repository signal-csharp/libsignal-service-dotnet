using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using libsignalservice.contacts.crypto;
using libsignalservice.contacts.entities;
using libsignalservice.push.exceptions;
using libsignalservice.util;
using org.whispersystems.curve25519;

namespace libsignalservice.push
{
    internal static class RemoteAttestationUtil
    {
        public static async Task<RemoteAttestation> GetAndVerifyRemoteAttestationAsync(PushServiceSocket socket,
            PushServiceSocket.ClientSet clientSet,
            string enclaveName,
            string mrenclave,
            string authorization)
        {
            Curve25519KeyPair keyPair = BuildKeyPair();
            ResponsePair result = await MakeAttestationRequestAsync(socket, clientSet, authorization, enclaveName, keyPair);
            RemoteAttestationResponse response = JsonUtil.FromJson<RemoteAttestationResponse>(result.body);

            return ValidateAndBuildRemoteAttestation(response, result.cookies, keyPair, mrenclave);
        }

        public static async Task<Dictionary<string, RemoteAttestation>> GetAndVerifyMultiRemoteAttestation(PushServiceSocket socket,
            PushServiceSocket.ClientSet clientSet,
            string enclaveName,
            string mrenclave,
            string authorization)
        {
            Curve25519KeyPair keyPair = BuildKeyPair();
            ResponsePair result = await MakeAttestationRequestAsync(socket, clientSet, authorization, enclaveName, keyPair);
            MultiRemoteAttestationResponse response = JsonUtil.FromJson<MultiRemoteAttestationResponse>(result.body);
            Dictionary<string, RemoteAttestation> attestations = new Dictionary<string, RemoteAttestation>();

            if (response.Attestations!.Count == 0 || response.Attestations.Count > 3)
            {
                throw new MalformedResponseException($"Incorrect number of attestations: {response.Attestations.Count}");
            }

            foreach (var entry in response.Attestations)
            {
                attestations.Add(entry.Key,
                    ValidateAndBuildRemoteAttestation(entry.Value, result.cookies, keyPair, mrenclave));
            }

            return attestations;
        }

        private static Curve25519KeyPair BuildKeyPair()
        {
            Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);
            return curve.generateKeyPair();
        }

        private static async Task<ResponsePair> MakeAttestationRequestAsync(PushServiceSocket socket,
            PushServiceSocket.ClientSet clientSet,
            string authorization,
            string enclaveName,
            Curve25519KeyPair keyPair)
        {
            RemoteAttestationRequest attestationRequest = new RemoteAttestationRequest(keyPair.getPublicKey());
            HttpResponseMessage response = await socket.MakeRequestAsync(clientSet, authorization, new List<string>(), $"/v1/attestation/{enclaveName}", "PUT", JsonUtil.ToJson(attestationRequest));
            HttpContent body = response.Content;

            if (body == null)
            {
                throw new MalformedResponseException("Empty response!");
            }

            return new ResponsePair(await body.ReadAsStringAsync(), ParseCookies(response));
        }

        private static List<string> ParseCookies(HttpResponseMessage response)
        {
            IEnumerable<string> rawCookies = response.Headers.GetValues("Set-Cookie");
            List<string> cookies = new List<string>();

            foreach (string cookie in rawCookies)
            {
                cookies.Add(cookie.Split(';')[0]);
            }

            return cookies;
        }

        private static RemoteAttestation ValidateAndBuildRemoteAttestation(RemoteAttestationResponse response,
            List<string> cookies,
            Curve25519KeyPair keyPair,
            string mrenclave)
        {
            RemoteAttestationKeys keys = new RemoteAttestationKeys(keyPair, response.ServerEphemeralPublic, response.ServerStaticPublic);
            Quote quote = new Quote(response.Quote);
            byte[] requestId = RemoteAttestationCipher.GetRequestId(keys, response);

            RemoteAttestationCipher.VerifyServerQuote(quote, response.ServerStaticPublic, mrenclave);

            RemoteAttestationCipher.VerifyIasSignature(response.Certificates, response.SignatureBody, response.Signature, quote);

            return new RemoteAttestation(requestId, keys, cookies);
        }

        private class ResponsePair
        {
            public readonly string body;
            public readonly List<string> cookies;

            public ResponsePair(string body, List<string> cookies)
            {
                this.body = body;
                this.cookies = cookies;
            }
        }
    }
}
