using System;

namespace libsignalservice.push
{
    public class UriFormatException : Exception
    {
        public UriFormatException()
        {
        }

        public UriFormatException(string message) : base(message)
        {
        }

        public UriFormatException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
