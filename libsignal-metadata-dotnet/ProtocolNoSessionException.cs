using System;
using System.Collections.Generic;
using System.Text;
using libsignal;

namespace libsignalmetadatadotnet
{
    public class ProtocolNoSessionException : ProtocolException
    {
        public ProtocolNoSessionException(NoSessionException inner, string sender, int senderDevice) : base(inner, sender, senderDevice)
        { }
    }
}
