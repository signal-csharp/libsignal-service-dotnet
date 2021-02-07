namespace libsignalservice.push.exceptions
{
    public class DeprecatedVersionException : NonSuccessfulResponseCodeException
    {
        public DeprecatedVersionException() : base(499)
        {
        }
    }
}
