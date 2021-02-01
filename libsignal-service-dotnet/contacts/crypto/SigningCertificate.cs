using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.OpenSsl;

namespace libsignalservice.contacts.crypto
{
    // TODO: Needs to be fully implemented
    public class SigningCertificate
    {
        private readonly System.Security.Cryptography.X509Certificates.X509Certificate2Collection path;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="certificateChain"></param>
        /// <exception cref="CryptographicException"></exception>
        public SigningCertificate(string certificateChain)
        {
            try
            {
                StringReader stringReader = new StringReader(WebUtility.UrlDecode(certificateChain));
                PemReader pemReader = new PemReader(stringReader);
                List<System.Security.Cryptography.X509Certificates.X509Certificate2> certificates = new List<System.Security.Cryptography.X509Certificates.X509Certificate2>();

                Org.BouncyCastle.X509.X509Certificate certificate;
                
                while ((certificate = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject()) != null)
                {
                    certificates.Add(new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded()));
                }

                path = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection(certificates.ToArray());

                VerifyDistinguishedName(path);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(null, ex);
            }
        }

        public void VerifySignature(string body, string encodedSignature)
        {
        }

        private void VerifyDistinguishedName(System.Security.Cryptography.X509Certificates.X509Certificate2Collection path)
        {
            System.Security.Cryptography.X509Certificates.X509Certificate2 leaf = path[0];
            string distinguishedName = leaf.SubjectName.Name;

            if ("CN=Intel SGX Attestation Report Signing,O=Intel Corporation,L=Santa Clara,ST=CA,C=US" != distinguishedName)
            {
                throw new CryptographicException($"Bad DN: {distinguishedName}");
            }
        }
    }
}
