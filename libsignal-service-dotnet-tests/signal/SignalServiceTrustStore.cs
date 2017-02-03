using System;
using System.IO;
using libsignalservice.push;

namespace signal
{
    public class SignalServiceTrustStore : TrustStore
    {
        public Stream getKeyStoreInputStream()
        {
            throw new NotImplementedException();
        }

        public string getKeyStorePassword()
        {
            throw new NotImplementedException();
        }
    }
}