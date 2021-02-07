namespace libsignalservice.push.exceptions
{
    public class UsernameMalformedException : NonSuccessfulResponseCodeException
    {
        public UsernameMalformedException() : base(400)
        {
        }
    }
}
