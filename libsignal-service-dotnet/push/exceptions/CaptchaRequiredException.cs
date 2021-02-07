namespace libsignalservice.push.exceptions
{
    public class CaptchaRequiredException : NonSuccessfulResponseCodeException
    {
        public CaptchaRequiredException() : base(402)
        {
        }
    }
}
