using System;
using System.Collections.Generic;
using System.Text;
using libsignal;
using libsignal.ecc;
using libsignal.state.impl;
using libsignal.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace libsignalmetadatadotnettests
{
    public class TestInMemorySignalProtocolStore : InMemorySignalProtocolStore
    {
        public TestInMemorySignalProtocolStore() : base(generateIdentityKeyPair(), generateRegistrationId())
        { }

        private static IdentityKeyPair generateIdentityKeyPair()
        {
            ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

            return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.getPublicKey()),
                                       identityKeyPairKeys.getPrivateKey());
        }

        private static uint generateRegistrationId()
        {
            return KeyHelper.generateRegistrationId(false); //TODO int?
        }
    }
}
