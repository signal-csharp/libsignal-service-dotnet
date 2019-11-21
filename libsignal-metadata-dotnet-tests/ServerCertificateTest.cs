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
    public class ServerCertificateTest
    {
        [TestMethod]
        public void TestBadFields()
        {
            var certificate = new libsignalmetadata.protobuf.ServerCertificate.Types.Certificate();

            try
            {
                new ServerCertificate(new libsignalmetadata.protobuf.ServerCertificate()
                {
                    Signature = ByteString.CopyFrom(new byte[64])
                }.ToByteArray());
                throw new Exception();
            }
            catch (InvalidCertificateException)
            {
                // good
            }

            try
            {
                new ServerCertificate(new libsignalmetadata.protobuf.ServerCertificate()
                {
                    Certificate = certificate.ToByteString(),
                    Signature = ByteString.CopyFrom(new byte[64])
                }.ToByteArray());
                throw new Exception();
            }
            catch (InvalidCertificateException)
            {
                // good
            }

            try
            {
                certificate.Id = 1;
                new ServerCertificate(new libsignalmetadata.protobuf.ServerCertificate()
                {
                    Certificate = certificate.ToByteString(),
                    Signature = ByteString.CopyFrom(new byte[64])
                }.ToByteArray());
                throw new Exception();
            }
            catch (InvalidCertificateException)
            {
                // good
            }
        }

        [TestMethod]
        public void TestSignature()
        {
            ECKeyPair trustRoot = Curve.generateKeyPair();
            ECKeyPair keyPair = Curve.generateKeyPair();

            var certificate = new libsignalmetadata.protobuf.ServerCertificate.Types.Certificate()
            {
                Id = 1,
                Key = ByteString.CopyFrom(keyPair.getPublicKey().serialize())
            };

            byte[] certificateBytes = certificate.ToByteArray();
            byte[] certificateSignature = Curve.calculateSignature(trustRoot.getPrivateKey(), certificateBytes);

            byte[] serialized = new libsignalmetadata.protobuf.ServerCertificate()
            {
                Certificate = ByteString.CopyFrom(certificateBytes),
                Signature = ByteString.CopyFrom(certificateSignature)
            }.ToByteArray();

            new CertificateValidator(trustRoot.getPublicKey()).Validate(new ServerCertificate(serialized));
        }

        [TestMethod]
        public void TestBadSignature()
        {
            ECKeyPair trustRoot = Curve.generateKeyPair();
            ECKeyPair keyPair = Curve.generateKeyPair();

            var certificate = new libsignalmetadata.protobuf.ServerCertificate.Types.Certificate()
            {
                Id = 1,
                Key = ByteString.CopyFrom(keyPair.getPublicKey().serialize())
            };

            byte[] certificateBytes = certificate.ToByteArray();
            byte[] certificateSignature = Curve.calculateSignature(trustRoot.getPrivateKey(), certificateBytes);

            for (int i = 0; i<certificateSignature.Length; i++)
            {
                for (int b = 0; b<8; b++)
                {
                    byte[] badSignature = new byte[certificateSignature.Length];
                    Array.Copy(certificateSignature, 0, badSignature, 0, badSignature.Length);

                    badSignature[i] = (byte)(badSignature[i] ^ (1 << b));


                    byte[] serialized = new libsignalmetadata.protobuf.ServerCertificate()
                    {
                        Certificate = ByteString.CopyFrom(certificateBytes),
                        Signature = ByteString.CopyFrom(badSignature)
                    }.ToByteArray();

                    try
                    {
                        new CertificateValidator(trustRoot.getPublicKey()).Validate(new ServerCertificate(serialized));
                        throw new Exception();
                    }
                    catch (InvalidCertificateException)
                    {
                        // good
                    }
                }
            }

            for (int i = 0; i<certificateBytes.Length; i++)
            {
                for (int b = 0; b<8; b++)
                {
                    byte[] badCertificate = new byte[certificateBytes.Length];
                    Array.Copy(certificateBytes, 0, badCertificate, 0, badCertificate.Length);

                    badCertificate[i] = (byte)(badCertificate[i] ^ (1 << b));

                    byte[] serialized = new libsignalmetadata.protobuf.ServerCertificate()
                    {
                        Certificate = ByteString.CopyFrom(badCertificate),
                        Signature = ByteString.CopyFrom(certificateSignature)
                    }.ToByteArray();

                    try
                    {
                        new CertificateValidator(trustRoot.getPublicKey()).Validate(new ServerCertificate(serialized));
                        throw new Exception();
                    }
                    catch (InvalidCertificateException)
                    {
                        // good
                    }
                }
            }

        }


    }
}
