using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using libsignal.util;
using libsignalservice.contacts.entities;
using libsignalservice.util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace libsignalservice.contacts.crypto
{
    public class ContactDiscoveryCipher
    {
        public DiscoveryRequest CreateDiscoveryRequest(IList<string> addressBook, RemoteAttestation remoteAttestation)
        {
            try
            {
                MemoryStream requestDataStream = new MemoryStream();

                foreach (string address in addressBook)
                {
                    byte[] bytes = ByteUtil.longToByteArray(long.Parse(address));
                    requestDataStream.Write(bytes, 0, bytes.Length);
                }

                byte[] requestData = requestDataStream.ToArray();
                byte[] nonce = Util.GetSecretBytes(12);
                GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());

                cipher.Init(true, new AeadParameters(new KeyParameter(remoteAttestation.Keys.ClientKey), 128, nonce));
                cipher.ProcessAadBytes(remoteAttestation.RequestId, 0, remoteAttestation.RequestId.Length);

                byte[] ciphertext = new byte[cipher.GetUpdateOutputSize(requestData.Length)];
                cipher.ProcessBytes(requestData, 0, requestData.Length, ciphertext, 0);

                byte[] tag = new byte[cipher.GetOutputSize(0)];
                cipher.DoFinal(tag, 0);

                return new DiscoveryRequest(addressBook.Count, remoteAttestation.RequestId, nonce, ciphertext, tag);
            }
            catch (Exception ex) when (ex is IOException || ex is InvalidCipherTextException)
            {
                // throw new AssertionError(e);
                throw new InvalidOperationException(null, ex);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="response"></param>
        /// <param name="remoteAttestation"></param>
        /// <returns></returns>
        /// <exception cref="InvalidCipherTextException"></exception>
        public byte[] GetDiscoveryResponseData(DiscoveryResponse response, RemoteAttestation remoteAttestation)
        {
            return Decrypt(remoteAttestation.Keys.ServerKey, response.Iv!, response.Data!, response.Mac!);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keys"></param>
        /// <param name="response"></param>
        /// <returns></returns>
        /// <exception cref="InvalidCipherTextException"></exception>
        public byte[] GetRequestId(RemoteAttestationKeys keys, RemoteAttestationResponse response)
        {
            return Decrypt(keys.ServerKey, response.Iv!, response.Ciphertext!, response.Tag!);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="quote"></param>
        /// <param name="serverPublicStatic"></param>
        /// <param name="mrenclave"></param>
        /// <exception cref="UnauthenticatedQuoteException"></exception>
        public void VerifyServerQuote(Quote quote, byte[] serverPublicStatic, string mrenclave)
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

                if (!quote.IsDebugQuote())
                {
                    // XXX Invert in production
                    throw new UnauthenticatedQuoteException("Expecting debug quote!");
                }
            }
            catch (IOException ex)
            {
                throw new UnauthenticatedQuoteException(ex);
            }
        }

        public void VerifyIasSignature(string certificates, string signatureBody, string signature, Quote quote)
        {
            try
            {
                SigningCertificate signingCertificate = new SigningCertificate(certificates);
                signingCertificate.VerifySignature(signatureBody, signature);

                SignatureBodyEntity signatureBodyEntity = JsonUtil.FromJson<SignatureBodyEntity>(signatureBody);

                if (!Enumerable.SequenceEqual(ByteUtil.trim(signatureBodyEntity.IsvEnclaveQuoteBody, 432), ByteUtil.trim(quote.QuoteBytes, 432)))
                {
                    throw new CryptographicException($"Signed quote is not the same as RA quote: {Hex.ToStringCondensed(signatureBodyEntity.IsvEnclaveQuoteBody!)} vs {Hex.ToStringCondensed(quote.QuoteBytes)}");
                }

                if ("OK" != signatureBodyEntity.IsvEnclaveQuoteStatus)
                {
                    throw new CryptographicException($"Quote status is: {signatureBodyEntity.IsvEnclaveQuoteStatus}");
                }

                DateTime datetime = DateTime.ParseExact(signatureBodyEntity.Timestamp, "yyy-MM-ddTHH:mm:ss.FFFFFF", CultureInfo.InvariantCulture);
                datetime = DateTime.SpecifyKind(datetime, DateTimeKind.Utc);
                if (datetime.AddDays(1) < DateTime.UtcNow)
                {
                    throw new CryptographicException("Signature is expired");
                }
            }
            catch (IOException ex)
            {
                throw new CryptographicException(null, ex);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="ciphertext"></param>
        /// <param name="tag"></param>
        /// <returns></returns>
        /// <exception cref="InvalidCipherTextException"></exception>
        private byte[] Decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] tag)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, iv));

            byte[] combined = ByteUtil.combine(ciphertext, tag);
            byte[] ciphertextOne = new byte[cipher.GetUpdateOutputSize(combined.Length)];
            cipher.ProcessBytes(combined, 0, combined.Length, ciphertextOne, 0);

            byte[] cipherTextTwo = new byte[cipher.GetOutputSize(0)];
            cipher.DoFinal(cipherTextTwo, 0);

            return ByteUtil.combine(ciphertextOne, cipherTextTwo);
        }
    }
}
