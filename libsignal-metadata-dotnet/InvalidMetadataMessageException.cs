using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalmetadata
{
    public class InvalidMetadataMessageException : Exception
    {
        public InvalidMetadataMessageException(string s) : base(s)
        { }

        public InvalidMetadataMessageException(Exception e) : base(e.Message, e)
        { }
    }
}
