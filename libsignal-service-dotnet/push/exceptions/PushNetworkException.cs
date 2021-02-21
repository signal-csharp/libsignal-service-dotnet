using System;

namespace libsignalservice.push.exceptions
{
    public class PushNetworkException : Exception
    {
        public PushNetworkException(Exception exception) : base(null, exception)
        {
        }

        public PushNetworkException(string s) : base(s)
        {
        }
    }
}
