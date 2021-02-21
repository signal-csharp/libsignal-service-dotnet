using System;

namespace libsignalservice.crypto
{
    public class InvalidCiphertextException : Exception
    {
        public InvalidCiphertextException(Exception nested) : base(null, nested)
        {
        }

        public InvalidCiphertextException(string s) : base(s)
        {
        }
    }
}
