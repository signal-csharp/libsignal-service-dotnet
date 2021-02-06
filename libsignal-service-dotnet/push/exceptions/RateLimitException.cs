namespace libsignalservice.push.exceptions
{
    public class RateLimitException : NonSuccessfulResponseCodeException
    {
        public RateLimitException(string s) : base(s)
        {
        }
    }
}
