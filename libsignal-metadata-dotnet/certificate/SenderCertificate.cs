using System;
using System.Collections.Generic;
using System.Text;
using Google.Protobuf;
using libsignal;
using libsignal.ecc;

namespace libsignalmetadatadotnet.certificate
{
    public class SenderCertificate
    {
        public ServerCertificate Signer { get; }
        public ECPublicKey Key { get; }
        public int SenderDeviceId { get; }
        public String Sender { get; }
        public long Expiration { get; }

        public byte[] Serialized { get; }
        public byte[] Certificate { get; }
        public byte[] Signature { get; }

        public SenderCertificate(byte[] serialized)
        {
            try
            {
                var wrapper = libsignalmetadata.protobuf.SenderCertificate.Parser.ParseFrom(serialized);

                if (wrapper.SignatureOneofCase != libsignalmetadata.protobuf.SenderCertificate.SignatureOneofOneofCase.Signature ||
                    wrapper.CertificateOneofCase != libsignalmetadata.protobuf.SenderCertificate.CertificateOneofOneofCase.Certificate)
                {
                    throw new InvalidCertificateException("Missing fields");
                }

                var certificate = libsignalmetadata.protobuf.SenderCertificate.Types.Certificate.Parser.ParseFrom(wrapper.Certificate);
                if (certificate.SignerOneofCase != libsignalmetadata.protobuf.SenderCertificate.Types.Certificate.SignerOneofOneofCase.Signer || 
                    certificate.IdentityKeyOneofCase != libsignalmetadata.protobuf.SenderCertificate.Types.Certificate.IdentityKeyOneofOneofCase.IdentityKey || 
                    certificate.SenderDeviceOneofCase != libsignalmetadata.protobuf.SenderCertificate.Types.Certificate.SenderDeviceOneofOneofCase.SenderDevice || 
                    certificate.ExpiresOneofCase != libsignalmetadata.protobuf.SenderCertificate.Types.Certificate.ExpiresOneofOneofCase.Expires ||
                    certificate.SenderOneofCase != libsignalmetadata.protobuf.SenderCertificate.Types.Certificate.SenderOneofOneofCase.Sender)
                {
                    throw new InvalidCertificateException("Missing fields");
                }

                Signer         = new ServerCertificate(certificate.Signer.ToByteArray());
                Key            = Curve.decodePoint(certificate.IdentityKey.ToByteArray(), 0);
                Sender         = certificate.Sender;
                SenderDeviceId = (int) certificate.SenderDevice;
                Expiration     = (long) certificate.Expires;

                Serialized  = serialized;
                Certificate = wrapper.Certificate.ToByteArray();
                Signature   = wrapper.Signature.ToByteArray();

            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidCertificateException(e);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidCertificateException(e);
            }
        }
    }
}
