using System;
using System.Collections.Generic;
using System.Text;
using libsignal;
using libsignal.exceptions;

namespace libsignalmetadatadotnet
{
    public class ProtocolUntrustedIdentityException : ProtocolException
    {
        public ProtocolUntrustedIdentityException(UntrustedIdentityException inner, string sender, int senderDevice) : base(inner, sender, senderDevice)
        { }
    }
}
