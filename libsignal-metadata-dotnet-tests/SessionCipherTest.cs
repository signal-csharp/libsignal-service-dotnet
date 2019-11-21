using System;
using System.Collections.Generic;
using System.Text;
using libsignal;
using libsignal.ecc;
using libsignal.protocol;
using libsignal.ratchet;
using libsignal.state;
using libsignal.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Strilanc.Value;

namespace libsignalmetadatadotnettests
{
    [TestClass]
    public class SessionCipherTest
    {
        [TestMethod]
        public void TestBasicSessionV3()
        {
            SessionRecord aliceSessionRecord = new SessionRecord();
            SessionRecord bobSessionRecord = new SessionRecord();

            InitializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());
            RunInteraction(aliceSessionRecord, bobSessionRecord);
        }

        [TestMethod]
        public void TestMessageKeyLimits()
        {
            SessionRecord aliceSessionRecord = new SessionRecord();
            SessionRecord bobSessionRecord = new SessionRecord();

            InitializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            aliceStore.StoreSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
            bobStore.StoreSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

            SessionCipher aliceCipher = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
            SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

            List<CiphertextMessage> inflight = new List<CiphertextMessage>();

            for (int i = 0; i<2010; i++)
            {
                inflight.Add(aliceCipher.encrypt(Encoding.ASCII.GetBytes("you've never been so hungry, you've never been so cold")));
            }

            bobCipher.decrypt(new SignalMessage(inflight[1000].serialize()));
            bobCipher.decrypt(new SignalMessage(inflight[inflight.Count-1].serialize()));

            try
            {
                bobCipher.decrypt(new SignalMessage(inflight[0].serialize()));
                throw new Exception("Should have failed!");
            }
            catch (DuplicateMessageException)
            {
                // good
            }
        }

        [TestMethod]
        private void RunInteraction(SessionRecord aliceSessionRecord, SessionRecord bobSessionRecord)
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            aliceStore.StoreSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
            bobStore.StoreSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

            SessionCipher aliceCipher = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
            SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

            byte[] alicePlaintext = Encoding.ASCII.GetBytes("This is a plaintext message.");
            CiphertextMessage message = aliceCipher.encrypt(alicePlaintext);
            byte[] bobPlaintext = bobCipher.decrypt(new SignalMessage(message.serialize()));

            CollectionAssert.AreEqual(alicePlaintext, bobPlaintext);

            byte[] bobReply = Encoding.ASCII.GetBytes("This is a message from Bob.");
            CiphertextMessage reply = bobCipher.encrypt(bobReply);
            byte[] receivedReply = aliceCipher.decrypt(new SignalMessage(reply.serialize()));

            CollectionAssert.AreEqual(bobReply, receivedReply);

            List<CiphertextMessage> aliceCiphertextMessages = new List<CiphertextMessage>();
            List<byte[]> alicePlaintextMessages = new List<byte[]>();

            for (int i = 0; i<50; i++)
            {
                alicePlaintextMessages.Add(Encoding.ASCII.GetBytes("смерть за смерть " + i));
                aliceCiphertextMessages.Add(aliceCipher.encrypt(Encoding.ASCII.GetBytes("смерть за смерть " + i)));
            }

            int seed = (int)DateTime.Now.Ticks;

            Shuffle(aliceCiphertextMessages, new Random(seed));
            Shuffle(alicePlaintextMessages, new Random(seed));

            for (int i = 0; i<aliceCiphertextMessages.Count / 2; i++)
            {
                byte[] receivedPlaintext = bobCipher.decrypt(new SignalMessage(aliceCiphertextMessages[i].serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, alicePlaintextMessages[i]);
            }

            List<CiphertextMessage> bobCiphertextMessages = new List<CiphertextMessage>();
            List<byte[]> bobPlaintextMessages = new List<byte[]>();

            for (int i = 0; i<20; i++)
            {
                bobPlaintextMessages.Add(Encoding.ASCII.GetBytes("смерть за смерть " + i));
                bobCiphertextMessages.Add(bobCipher.encrypt(Encoding.ASCII.GetBytes("смерть за смерть " + i)));
            }

            seed = (int)DateTime.Now.Ticks;

            Shuffle(bobCiphertextMessages, new Random(seed));
            Shuffle(bobPlaintextMessages, new Random(seed));

            for (int i = 0; i<bobCiphertextMessages.Count / 2; i++)
            {
                byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages[i].serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, bobPlaintextMessages[i]);
            }

            for (int i = aliceCiphertextMessages.Count/2; i<aliceCiphertextMessages.Count; i++)
            {
                byte[] receivedPlaintext = bobCipher.decrypt(new SignalMessage(aliceCiphertextMessages[i].serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, alicePlaintextMessages[i]);
            }

            for (int i = bobCiphertextMessages.Count / 2; i<bobCiphertextMessages.Count; i++)
            {
                byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages[i].serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, bobPlaintextMessages[i]);
            }
        }

        private void InitializeSessionsV3(SessionState aliceSessionState, SessionState bobSessionState)
        {
            ECKeyPair aliceIdentityKeyPair = Curve.generateKeyPair();
            IdentityKeyPair aliceIdentityKey = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                                                                       aliceIdentityKeyPair.getPrivateKey());
            ECKeyPair aliceBaseKey = Curve.generateKeyPair();
            ECKeyPair aliceEphemeralKey = Curve.generateKeyPair();

            ECKeyPair alicePreKey = aliceBaseKey;

            ECKeyPair bobIdentityKeyPair = Curve.generateKeyPair();
            IdentityKeyPair bobIdentityKey = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
                                                                       bobIdentityKeyPair.getPrivateKey());
            ECKeyPair bobBaseKey = Curve.generateKeyPair();
            ECKeyPair bobEphemeralKey = bobBaseKey;

            ECKeyPair bobPreKey = Curve.generateKeyPair();

            AliceSignalProtocolParameters aliceParameters = AliceSignalProtocolParameters.newBuilder()
                                                                                         .setOurBaseKey(aliceBaseKey)
                                                                                         .setOurIdentityKey(aliceIdentityKey)
                                                                                         .setTheirOneTimePreKey(May.NoValue)
                                                                                         .setTheirRatchetKey(bobEphemeralKey.getPublicKey())
                                                                                         .setTheirSignedPreKey(bobBaseKey.getPublicKey())
                                                                                         .setTheirIdentityKey(bobIdentityKey.getPublicKey())
                                                                                         .create();

            BobSignalProtocolParameters bobParameters = BobSignalProtocolParameters.newBuilder()
                                                                                   .setOurRatchetKey(bobEphemeralKey)
                                                                                   .setOurSignedPreKey(bobBaseKey)
                                                                                   .setOurOneTimePreKey(May.NoValue)
                                                                                   .setOurIdentityKey(bobIdentityKey)
                                                                                   .setTheirIdentityKey(aliceIdentityKey.getPublicKey())
                                                                                   .setTheirBaseKey(aliceBaseKey.getPublicKey())
                                                                                   .create();

            RatchetingSession.initializeSession(aliceSessionState, aliceParameters);
            RatchetingSession.initializeSession(bobSessionState, bobParameters);
        }

        public static void Shuffle<T>(IList<T> list, Random rng)
        {
            int n = list.Count;
            while (n > 1)
            {
                n--;
                int k = rng.Next(n + 1);
                T value = list[k];
                list[k] = list[n];
                list[n] = value;
            }
        }
    }
}
