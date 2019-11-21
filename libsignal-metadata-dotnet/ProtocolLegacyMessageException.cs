using System;
using System.Collections.Generic;
using System.Text;
using libsignal;

namespace libsignalmetadatadotnet
{
    public class ProtocolLegacyMessageException : ProtocolException
    {
        public ProtocolLegacyMessageException(LegacyMessageException inner, string sender, int senderDevice) : base(inner, sender, senderDevice)
        { }
    }
}
