using System;
using System.Collections.Generic;
using System.Text;
using Google.Protobuf;
using libsignal;
using libsignal.ecc;

namespace libsignalmetadatadotnet.certificate
{
    public class ServerCertificate
    {
        public int KeyId { get; }
        public ECPublicKey Key { get; }

        public byte[] Serialized { get; }
        public byte[] Certificate { get; }
        public byte[] Signature { get; }

        public ServerCertificate(byte[] serialized)
        {
            try
            {
                var wrapper = libsignalmetadata.protobuf.ServerCertificate.Parser.ParseFrom(serialized);
                if (wrapper.CertificateOneofCase != libsignalmetadata.protobuf.ServerCertificate.CertificateOneofOneofCase.Certificate ||
                    wrapper.SignatureOneofCase != libsignalmetadata.protobuf.ServerCertificate.SignatureOneofOneofCase.Signature)
                {
                    throw new InvalidCertificateException("Missing fields");
                }

                var certificate = libsignalmetadata.protobuf.ServerCertificate.Types.Certificate.Parser.ParseFrom(wrapper.Certificate);

                if (certificate.IdOneofCase !=  libsignalmetadata.protobuf.ServerCertificate.Types.Certificate.IdOneofOneofCase.Id ||
                    certificate.KeyOneofCase != libsignalmetadata.protobuf.ServerCertificate.Types.Certificate.KeyOneofOneofCase.Key)
                {
                    throw new InvalidCertificateException("Missing fields");
                }

                KeyId       = (int)certificate.Id;
                Key         = Curve.decodePoint(certificate.Key.ToByteArray(), 0);
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
