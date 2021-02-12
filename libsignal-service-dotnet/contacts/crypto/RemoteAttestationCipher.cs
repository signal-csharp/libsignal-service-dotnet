using System;
using System.Globalization;
using System.IO;
using System.Linq;
using libsignal.util;
using libsignalservice.contacts.entities;
using libsignalservice.util;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;

namespace libsignalservice.contacts.crypto
{
    internal static class RemoteAttestationCipher
    {
        private const long SIGNATURE_BODY_VERSION = 3;

        public static byte[] GetRequestId(RemoteAttestationKeys keys, RemoteAttestationResponse response)
        {
            return AesCipher.Decrypt(keys.ServerKey, response.Iv, response.Ciphertext, response.Tag);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="quote"></param>
        /// <param name="serverPublicStatic"></param>
        /// <param name="mrenclave"></param>
        /// <exception cref="UnauthenticatedQuoteException"></exception>
        public static void VerifyServerQuote(Quote quote, byte[] serverPublicStatic, string mrenclave)
        {
            try
            {
                byte[] theirServerPublicStatic = new byte[serverPublicStatic.Length];
                Array.Copy(quote.ReportData, 0, theirServerPublicStatic, 0, theirServerPublicStatic.Length);

                if (!Enumerable.SequenceEqual(theirServerPublicStatic, serverPublicStatic))
                {
                    throw new UnauthenticatedQuoteException("Response quote has unauthenticated report data!");
                }

                if (!Enumerable.SequenceEqual(Hex.FromStringCondensed(mrenclave), quote.Mrenclave))
                {
                    throw new UnauthenticatedQuoteException($"The response quote has the wrong mrenclave value in it: {Hex.ToStringCondensed(quote.Mrenclave)}");
                }

                if (quote.IsDebugQuote())
                {
                    throw new UnauthenticatedQuoteException("Received quote for debuggable enclave");
                }
            }
            catch (IOException ex)
            {
                throw new UnauthenticatedQuoteException(ex);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="certificates"></param>
        /// <param name="signatureBody"></param>
        /// <param name="signature"></param>
        /// <param name="quote"></param>
        /// <exception cref="SignatureException"></exception>
        public static void VerifyIasSignature(string certificates, string signatureBody, string signature, Quote quote)
        {
            if (string.IsNullOrWhiteSpace(certificates))
            {
                throw new SignatureException("No certificates.");
            }

            try
            {
                SigningCertificate signingCertificate = new SigningCertificate(certificates);
                signingCertificate.VerifySignature(signatureBody, signature);

                SignatureBodyEntity signatureBodyEntity = JsonUtil.FromJson<SignatureBodyEntity>(signatureBody);

                if (signatureBodyEntity.Version != SIGNATURE_BODY_VERSION)
                {
                    throw new SignatureException($"Unexpected signed quote version {signatureBodyEntity.Version}");
                }

                if (!Enumerable.SequenceEqual(ByteUtil.trim(signatureBodyEntity.IsvEnclaveQuoteBody, 432), ByteUtil.trim(quote.QuoteBytes, 432)))
                {
                    throw new SignatureException($"Signed quote is not the same as RA quote: {Hex.ToStringCondensed(signatureBodyEntity.IsvEnclaveQuoteBody!)} vs {Hex.ToStringCondensed(quote.QuoteBytes)}");
                }

                if ("OK" != signatureBodyEntity.IsvEnclaveQuoteStatus)
                {
                    throw new SignatureException($"Quote status is: {signatureBodyEntity.IsvEnclaveQuoteStatus}");
                }

                DateTime datetime = DateTime.ParseExact(signatureBodyEntity.Timestamp, "yyyy-MM-ddTHH:mm:ss.FFFFFF", CultureInfo.InvariantCulture);
                datetime = DateTime.SpecifyKind(datetime, DateTimeKind.Utc);
                if (datetime.AddDays(1) < DateTime.UtcNow)
                {
                    throw new SignatureException("Signature is expired");
                }
            }
            catch (PkixCertPathValidatorException ex)
            {
                throw new SignatureException(null, ex);
            }
        }
    }
}
