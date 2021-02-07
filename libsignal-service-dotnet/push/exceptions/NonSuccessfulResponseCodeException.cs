using System;

namespace libsignalservice.push.exceptions
{
    public class NonSuccessfulResponseCodeException : Exception
    {
        public int Code { get; }

        public NonSuccessfulResponseCodeException(int code)
        {
            Code = code;
        }

        public NonSuccessfulResponseCodeException(int code, string s) : base(s)
        {
            Code = code;
        }
    }
}
