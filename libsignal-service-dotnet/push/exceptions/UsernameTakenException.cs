namespace libsignalservice.push.exceptions
{
    public class UsernameTakenException : NonSuccessfulResponseCodeException
    {
        public UsernameTakenException() : base(409)
        {
        }
    }
}
