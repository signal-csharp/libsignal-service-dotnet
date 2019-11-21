using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalmetadatadotnet.certificate
{
    public class InvalidCertificateException : Exception
    {
        public InvalidCertificateException(string s) : base(s)
        { }

        public InvalidCertificateException(Exception e) : base(e.Message, e)
        { }
    }
}
