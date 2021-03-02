using System;
using libsignal;

namespace libsignalservice.crypto
{
    public class UntrustedIdentityException : Exception
    {
        public IdentityKey IdentityKey { get; }
        public string? Identifier { get; }

        public UntrustedIdentityException(string s, string? identifier, IdentityKey identityKey) : base(s)
        {
            Identifier = identifier;
            IdentityKey = identityKey;
        }

        public UntrustedIdentityException(UntrustedIdentityException ex) :
            this(ex.Message, ex.Identifier, ex.IdentityKey)
        {
        }
    }
}
