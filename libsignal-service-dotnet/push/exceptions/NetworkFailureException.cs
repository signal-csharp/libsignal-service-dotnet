using System;

namespace libsignalservice.push.exceptions
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class NetworkFailureException : Exception
    {
        public String E164number { get; }

        public NetworkFailureException(String e164number, Exception nested)
                  : base(nested.Message)
        {
            E164number = e164number;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
