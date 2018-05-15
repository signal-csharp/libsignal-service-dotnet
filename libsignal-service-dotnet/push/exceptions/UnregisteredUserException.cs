using System;

namespace libsignalservice.push.exceptions
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class UnregisteredUserException : Exception
    {
        public String e164number { get; }

        public UnregisteredUserException(String e164number, Exception exception)
            : base(exception.Message)

        {
            this.e164number = e164number;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
