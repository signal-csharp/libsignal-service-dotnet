using libsignaldotnet.push.http;
using libsignalservice.crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace libsignalservice.push.http
{
    internal class ProfileCipherOutputStreamFactory : OutputStreamFactory
    {
        private readonly byte[] Key;

        internal ProfileCipherOutputStreamFactory(byte[] key)
        {
            Key = key;
        }

        public DigestingOutputStream CreateFor(Stream wrap)
        {
            return new ProfileCipherOutputStream(wrap, Key);
        }
    }
}
