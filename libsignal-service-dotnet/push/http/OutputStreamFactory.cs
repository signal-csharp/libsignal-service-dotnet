using libsignalservice.crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace libsignaldotnet.push.http
{
    public interface OutputStreamFactory
    {
        DigestingOutputStream CreateFor(Stream wrap);
    }
}
