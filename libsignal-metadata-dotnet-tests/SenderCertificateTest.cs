using System;
using System.Collections.Generic;
using System.Text;
using Google.Protobuf;
using libsignal.ecc;
using libsignalmetadatadotnet.certificate;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace libsignalmetadatadotnettests
{
    [TestClass]
    public class SenderCertificateTest
    {
        private readonly ECKeyPair TrustRoot = Curve.generateKeyPair();

        [TestMethod]
        public void TestSignature()
        {
            ECKeyPair serverKey = Curve.generateKeyPair();
            ECKeyPair key = Curve.generateKeyPair();


            byte[] certificateBytes = new libsignalmetadata.protobuf.SenderCertificate.Types.Certificate()
            {
                Sender = "+14152222222",
                SenderDevice = 1,
                Expires = 31337,
                IdentityKey = ByteString.CopyFrom(key.getPublicKey().serialize()),
                Signer = GetServerCertificate(serverKey)
            }.ToByteArray();

            byte[] certificateSignature = Curve.calculateSignature(serverKey.getPrivateKey(), certificateBytes);

            SenderCertificate senderCertificate = new SenderCertificate(new libsignalmetadata.protobuf.SenderCertificate()
            {
                Certificate = ByteString.CopyFrom(certificateBytes),
                Signature = ByteString.CopyFrom(certificateSignature)
            }.ToByteArray());

            new CertificateValidator(TrustRoot.getPublicKey()).Validate(senderCertificate, 31336);
        }

        [TestMethod]
        public void TestExpiredSignature()
        {
            ECKeyPair serverKey = Curve.generateKeyPair();
            ECKeyPair key = Curve.generateKeyPair();

            byte[] certificateBytes = new libsignalmetadata.protobuf.SenderCertificate.Types.Certificate()
            {
                Sender = "+14152222222",
                SenderDevice = 1,
                Expires = 31337,
                IdentityKey = ByteString.CopyFrom(key.getPublicKey().serialize()),
                Signer = GetServerCertificate(serverKey)
            }.ToByteArray();

            byte[] certificateSignature = Curve.calculateSignature(serverKey.getPrivateKey(), certificateBytes);

            SenderCertificate senderCertificate = new SenderCertificate(new libsignalmetadata.protobuf.SenderCertificate()
            {
                Certificate = ByteString.CopyFrom(certificateBytes),
                Signature = ByteString.CopyFrom(certificateSignature)
            }.ToByteArray());

            try
            {
                new CertificateValidator(TrustRoot.getPublicKey()).Validate(senderCertificate, 31338);
                throw new Exception();
            }
            catch (InvalidCertificateException)
            {
                // good
            }
        }

        [TestMethod]
        public void TestBadSignature()
        {
            ECKeyPair serverKey = Curve.generateKeyPair();
            ECKeyPair key = Curve.generateKeyPair();

            byte[] certificateBytes = new libsignalmetadata.protobuf.SenderCertificate.Types.Certificate()
            {
                Sender = "+14152222222",
                SenderDevice = 1,
                Expires = 31337,
                IdentityKey = ByteString.CopyFrom(key.getPublicKey().serialize()),
                Signer = GetServerCertificate(serverKey)
            }.ToByteArray();

            byte[] certificateSignature = Curve.calculateSignature(serverKey.getPrivateKey(), certificateBytes);

            for (int i = 0; i<certificateSignature.Length; i++)
            {
                for (int b = 0; b<8; b++)
                {
                    byte[] badSignature = new byte[certificateSignature.Length];
                    Array.Copy(certificateSignature, 0, badSignature, 0, certificateSignature.Length);

                    badSignature[i] = (byte)(badSignature[i] ^ 1 << b);

                    SenderCertificate senderCertificate = new SenderCertificate(new libsignalmetadata.protobuf.SenderCertificate()
                    {
                        Certificate = ByteString.CopyFrom(certificateBytes),
                        Signature = ByteString.CopyFrom(badSignature)
                    }.ToByteArray());

                    try
                    {
                        new CertificateValidator(TrustRoot.getPublicKey()).Validate(senderCertificate, 31336);
                        throw new Exception();
                    }
                    catch (InvalidCertificateException)
                    {
                        // good
                    }
                }
            }

        }


        private libsignalmetadata.protobuf.ServerCertificate GetServerCertificate(ECKeyPair serverKey)
        {
            byte[] certificateBytes = new libsignalmetadata.protobuf.ServerCertificate.Types.Certificate()
            {
                Id = 1,
                Key = ByteString.CopyFrom(serverKey.getPublicKey().serialize())
            }.ToByteArray();

            byte[] certificateSignature = Curve.calculateSignature(TrustRoot.getPrivateKey(), certificateBytes);

            return new libsignalmetadata.protobuf.ServerCertificate()
            {
                Certificate = ByteString.CopyFrom(certificateBytes),
                Signature = ByteString.CopyFrom(certificateSignature)
            };
        }
    }
}
