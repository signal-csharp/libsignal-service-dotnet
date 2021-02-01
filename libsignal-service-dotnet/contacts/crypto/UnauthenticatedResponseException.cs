using System;

namespace libsignalservice.contacts.crypto
{
    public class UnauthenticatedResponseException : Exception
    {
        public UnauthenticatedResponseException(Exception e) : base(null, e)
        {
        }

        public UnauthenticatedResponseException(string s) : base(s)
        {
        }
    }
}
