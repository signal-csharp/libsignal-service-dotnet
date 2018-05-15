using System;

namespace libsignalservice.push.exceptions
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class PushNetworkException : Exception
    {
        public Exception exception;

        public PushNetworkException(Exception exception)
            : base(exception.Message)
        {
            this.exception = exception;
        }

        public override string ToString()
        {
            return base.ToString() + " [" + exception + "]";
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
