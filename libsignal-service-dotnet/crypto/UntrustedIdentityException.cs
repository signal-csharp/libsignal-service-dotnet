using libsignal;
using System;

namespace libsignalservice.crypto
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class UntrustedIdentityException : Exception
    {
        public IdentityKey IdentityKey { get; }
        public String E164number { get; }

        public UntrustedIdentityException(String s, String e164number, IdentityKey identityKey)
                  : base(s)
        {
            E164number = e164number;
            IdentityKey = identityKey;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
