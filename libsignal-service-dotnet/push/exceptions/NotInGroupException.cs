namespace libsignalservice.push.exceptions
{
    internal class NotInGroupException : NonSuccessfulResponseCodeException
    {
        public NotInGroupException() : base(403)
        {
        }
    }
}
