using System;

namespace libsignalservice.contacts.crypto
{
    internal class UnauthenticatedQuoteException : Exception
    {
        public UnauthenticatedQuoteException(string s) : base(s)
        {
        }

        public UnauthenticatedQuoteException(Exception nested) : base(null, nested)
        {
        }
    }
}
