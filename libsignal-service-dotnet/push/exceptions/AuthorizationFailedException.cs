namespace libsignalservice.push.exceptions
{
    public class AuthorizationFailedException : NonSuccessfulResponseCodeException
    {
        public AuthorizationFailedException(int code, string s) : base(code, s)
        {
        }
    }
}
