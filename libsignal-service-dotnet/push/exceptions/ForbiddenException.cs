namespace libsignalservice.push.exceptions
{
    public class ForbiddenException : NonSuccessfulResponseCodeException
    {
        public ForbiddenException() : base(403)
        {
        }
    }
}
