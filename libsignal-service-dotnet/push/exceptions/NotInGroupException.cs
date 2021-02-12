namespace libsignalservice.push.exceptions
{
    public class NotInGroupException : NonSuccessfulResponseCodeException
    {
        public NotInGroupException() : base(403)
        {
        }
    }
}
