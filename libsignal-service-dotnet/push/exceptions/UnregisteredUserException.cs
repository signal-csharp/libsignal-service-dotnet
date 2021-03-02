using System;

namespace libsignalservice.push.exceptions
{
    public class UnregisteredUserException : Exception
    {
        public string? E164Number { get; }

        public UnregisteredUserException(string? e164number, Exception exception)
            : base(exception.Message)
        {
            E164Number = e164number;
        }
    }
}
