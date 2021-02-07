namespace libsignalservice.push.exceptions
{
    public class NoContentException : NonSuccessfulResponseCodeException
    {
        public NoContentException(string s) : base(204, s)
        {
        }
    }
}
