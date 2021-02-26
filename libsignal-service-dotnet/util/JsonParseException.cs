using System;

namespace libsignalservice.util
{
    public class JsonParseException : Exception
    {
        public JsonParseException(Exception ex) : base(null, ex)
        {
        }
    }
}
