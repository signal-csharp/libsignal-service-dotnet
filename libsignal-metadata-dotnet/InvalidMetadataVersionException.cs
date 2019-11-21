using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalmetadata
{
    public class InvalidMetadataVersionException : Exception
    {
        public InvalidMetadataVersionException(string s) : base(s)
        { }
    }
}
