using System;

namespace libsignalservice.contacts.crypto
{
    internal class UnauthenticatedResponseException : Exception
    {
        public UnauthenticatedResponseException(Exception e) : base(null, e)
        {
        }

        public UnauthenticatedResponseException(string s) : base(s)
        {
        }
    }
}
