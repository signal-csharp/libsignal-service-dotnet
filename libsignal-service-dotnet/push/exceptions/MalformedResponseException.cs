using System;

namespace libsignalservice.push.exceptions
{
    /// <summary>
    /// Indicates that a response is malformed or otherwise in an unexpected format.
    /// </summary>
    public class MalformedResponseException : Exception
    {
        public MalformedResponseException(string message) : base(message)
        {
        }

        public MalformedResponseException(string message, Exception ex) : base(message, ex)
        {
        }
    }
}
