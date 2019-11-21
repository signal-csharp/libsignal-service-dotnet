using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Google.Protobuf;
using libsignal;
using libsignal.ecc;
using libsignal.state;
using libsignal.util;
using libsignalmetadata;
using libsignalmetadatadotnet;
using libsignalmetadatadotnet.certificate;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace libsignalmetadatadotnettests
{
    [TestClass]
    public class SealedSessionCipherTest
    {
        [TestMethod]
        public void TestEncryptDecrypt()
        {
            TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            TestInMemorySignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            InitializeSessions(aliceStore, bobStore);

            ECKeyPair trustRoot = Curve.generateKeyPair();
            SenderCertificate senderCertificate = CreateCertificateFor(trustRoot, "+14151111111", 1, aliceStore.GetIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
            SealedSessionCipher aliceCipher = new SealedSessionCipher(aliceStore, new SignalProtocolAddress("+14151111111", 1));

            byte[] ciphertext = aliceCipher.Encrypt(new SignalProtocolAddress("+14152222222", 1),
                                                    senderCertificate, Encoding.ASCII.GetBytes("smert za smert"));


            SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, new SignalProtocolAddress("+14152222222", 1));

            (SignalProtocolAddress, byte[]) plaintext = bobCipher.Decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);

            CollectionAssert.AreEqual(plaintext.Item2, Encoding.ASCII.GetBytes("smert za smert"));
            Assert.AreEqual(plaintext.Item1.Name, "+14151111111");
            Assert.AreEqual(plaintext.Item1.DeviceId, (uint)1);
        }

        [TestMethod]
        public void TestEncryptDecryptUntrusted()
        {
            TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            TestInMemorySignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            InitializeSessions(aliceStore, bobStore);

            ECKeyPair trustRoot = Curve.generateKeyPair();
            ECKeyPair falseTrustRoot = Curve.generateKeyPair();
            SenderCertificate senderCertificate = CreateCertificateFor(falseTrustRoot, "+14151111111", 1, aliceStore.GetIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
            SealedSessionCipher aliceCipher = new SealedSessionCipher(aliceStore, new SignalProtocolAddress("+14151111111", 1));

            byte[] ciphertext = aliceCipher.Encrypt(new SignalProtocolAddress("+14152222222", 1),
                                                    senderCertificate, Encoding.ASCII.GetBytes("и вот я"));

            SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, new SignalProtocolAddress("+14152222222", 1));

            try
            {
                bobCipher.Decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);
                throw new Exception();
            }
            catch (InvalidMetadataMessageException)
            {
                // good
            }
        }

        [TestMethod]
        public void TestEncryptFromWrongIdentity()
        {
            TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            TestInMemorySignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            InitializeSessions(aliceStore, bobStore);

            ECKeyPair trustRoot = Curve.generateKeyPair();
            ECKeyPair randomKeyPair = Curve.generateKeyPair();
            SenderCertificate senderCertificate = CreateCertificateFor(trustRoot, "+14151111111", 1, randomKeyPair.getPublicKey(), 31337);
            SealedSessionCipher aliceCipher = new SealedSessionCipher(aliceStore, new SignalProtocolAddress("+14151111111", 1));

            byte[] ciphertext = aliceCipher.Encrypt(new SignalProtocolAddress("+14152222222", 1),
                                                    senderCertificate, Encoding.ASCII.GetBytes("smert za smert"));


            SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, new SignalProtocolAddress("+14152222222", 1));

            try
            {
                bobCipher.Decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);
            }
            catch (InvalidMetadataMessageException)
            {
                // good
            }
        }

        private SenderCertificate CreateCertificateFor(ECKeyPair trustRoot, String sender, int deviceId, ECPublicKey identityKey, long expires)
        {
            ECKeyPair serverKey = Curve.generateKeyPair();

            byte[] serverCertificateBytes = new libsignalmetadata.protobuf.ServerCertificate.Types.Certificate()
            {
                Id = 1,
                Key = ByteString.CopyFrom(serverKey.getPublicKey().serialize())
            }.ToByteArray();

            byte[] serverCertificateSignature = Curve.calculateSignature(trustRoot.getPrivateKey(), serverCertificateBytes);

            ServerCertificate serverCertificate = new ServerCertificate(new libsignalmetadata.protobuf.ServerCertificate()
            {
                Certificate = ByteString.CopyFrom(serverCertificateBytes),
                Signature = ByteString.CopyFrom(serverCertificateSignature)
            }.ToByteArray());

            byte[] senderCertificateBytes = new libsignalmetadata.protobuf.SenderCertificate.Types.Certificate
            {
                Sender = sender,
                SenderDevice = (uint)deviceId,
                IdentityKey = ByteString.CopyFrom(identityKey.serialize()),
                Expires = (ulong)expires,
                Signer = libsignalmetadata.protobuf.ServerCertificate.Parser.ParseFrom(serverCertificate.Serialized)
            }.ToByteArray();

            byte[] senderCertificateSignature = Curve.calculateSignature(serverKey.getPrivateKey(), senderCertificateBytes);

            return new SenderCertificate(new libsignalmetadata.protobuf.SenderCertificate()
            {
                Certificate = ByteString.CopyFrom(senderCertificateBytes),
                Signature = ByteString.CopyFrom(senderCertificateSignature)
            }.ToByteArray());
        }

        private void InitializeSessions(TestInMemorySignalProtocolStore aliceStore, TestInMemorySignalProtocolStore bobStore)
        {
            ECKeyPair bobPreKey = Curve.generateKeyPair();
            IdentityKeyPair bobIdentityKey = bobStore.GetIdentityKeyPair();
            SignedPreKeyRecord bobSignedPreKey = KeyHelper.generateSignedPreKey(bobIdentityKey, 2);

            PreKeyBundle bobBundle = new PreKeyBundle(1, 1, 1, bobPreKey.getPublicKey(), 2, bobSignedPreKey.getKeyPair().getPublicKey(), bobSignedPreKey.getSignature(), bobIdentityKey.getPublicKey());
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, new SignalProtocolAddress("+14152222222", 1));
            aliceSessionBuilder.process(bobBundle);

            bobStore.StoreSignedPreKey(2, bobSignedPreKey);
            bobStore.StorePreKey(1, new PreKeyRecord(1, bobPreKey));

        }
    }
}
