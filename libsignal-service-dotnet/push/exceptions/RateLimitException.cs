using System;

namespace libsignalservice.push.exceptions
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class RateLimitException : NonSuccessfulResponseCodeException
    {
        public RateLimitException(String s)
            : base(s)
        {
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
