using System;

namespace libsignalservice.util
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class InvalidNumberException : Exception
    {
        public InvalidNumberException(String s)
            : base(s)
        {
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
