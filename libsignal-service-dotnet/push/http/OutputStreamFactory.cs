using libsignalservice.crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace libsignaldotnet.push.http
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public interface OutputStreamFactory
    {
        DigestingOutputStream CreateFor(Stream wrap);
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
