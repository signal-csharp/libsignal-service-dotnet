namespace libsignalservice.push.exceptions
{
    internal class ForbiddenException : NonSuccessfulResponseCodeException
    {
        public ForbiddenException() : base(403)
        {
        }
    }
}
