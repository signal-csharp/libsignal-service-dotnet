using System;
using System.Collections.Generic;
using System.Text;
using libsignal;
using libsignal.ecc;

namespace libsignalmetadatadotnet.certificate
{
    public class CertificateValidator
    {
        private static readonly HashSet<int> REVOKED = new HashSet<int>();
        private readonly ECPublicKey TrustRoot;

        public CertificateValidator(ECPublicKey trustRoot)
        {
            TrustRoot = trustRoot;
        }

        public void Validate(SenderCertificate certificate, long validationTime)
        {
            try
            {
                ServerCertificate serverCertificate = certificate.Signer;
                Validate(serverCertificate);

                if (!Curve.verifySignature(serverCertificate.Key, certificate.Certificate, certificate.Signature))
                {
                    throw new InvalidCertificateException("Signature failed");
                }

                if (validationTime > certificate.Expiration)
                {
                    throw new InvalidCertificateException("Certificate is expired");
                }
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidCertificateException(e);
            }
        }

        // VisibleForTesting
        public void Validate(ServerCertificate certificate)
        {
            try
            {
                if (!Curve.verifySignature(TrustRoot, certificate.Certificate, certificate.Signature))
                {
                    throw new InvalidCertificateException("Signature failed");
                }

                if (REVOKED.Contains(certificate.KeyId))
                {
                    throw new InvalidCertificateException("Server certificate has been revoked");
                }
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidCertificateException(e);
            }
        }
    }
}
