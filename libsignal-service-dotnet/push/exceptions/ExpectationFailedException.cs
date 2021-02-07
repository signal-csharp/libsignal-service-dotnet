namespace libsignalservice.push.exceptions
{
    public class ExpectationFailedException : NonSuccessfulResponseCodeException
    {
        public ExpectationFailedException() : base(417)
        {
        }
    }
}
