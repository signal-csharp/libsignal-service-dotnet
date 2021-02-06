using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using libsignalservice.util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace libsignalservice.contacts.crypto
{
    public class SigningCertificate
    {
        private readonly PkixCertPath path;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="certificateChain"></param>
        /// <exception cref="PkixCertPathValidatorException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public SigningCertificate(string certificateChain)
        {
            StringReader stringReader = new StringReader(certificateChain);
            PemReader pemReader = new PemReader(stringReader);
            List<X509Certificate> certificates = new List<X509Certificate>();

            X509Certificate certificate;

            while ((certificate = (X509Certificate)pemReader.ReadObject()) != null)
            {
                certificates.Add(certificate);
            }

            path = new PkixCertPath(certificates);

            Org.BouncyCastle.Utilities.Collections.ISet trustAnchors = new Org.BouncyCastle.Utilities.Collections.HashSet(new TrustAnchor[] { new TrustAnchor(certificates.Last(), null) });
            PkixParameters pkixParameters = new PkixParameters(trustAnchors);
            pkixParameters.IsRevocationEnabled = false;
            PkixCertPathValidator certPathValidator = new PkixCertPathValidator();
            certPathValidator.Validate(path, pkixParameters);
            VerifyDistinguishedName(path);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="body"></param>
        /// <param name="encodedSignature"></param>
        /// <exception cref="SignatureException"></exception>
        public void VerifySignature(string body, string encodedSignature)
        {
            ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
            signer.Init(false, ((X509Certificate)path.Certificates[0]).GetPublicKey());
            byte[] input = Encoding.UTF8.GetBytes(body);
            signer.BlockUpdate(input, 0, input.Length);
            if (!signer.VerifySignature(Base64.Decode(encodedSignature)))
            {
                throw new SignatureException("Signature verification failed.");
            }
        }

        private void VerifyDistinguishedName(PkixCertPath path)
        {
            X509Certificate leaf = (X509Certificate)path.Certificates[0];
            string distinguishedName = leaf.SubjectDN.ToString();

            if ("C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX Attestation Report Signing" != distinguishedName)
            {
                throw new CryptographicException($"Bad DN: {distinguishedName}");
            }
        }
    }
}
