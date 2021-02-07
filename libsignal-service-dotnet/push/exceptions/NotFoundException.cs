namespace libsignalservice.push.exceptions
{
    public class NotFoundException : NonSuccessfulResponseCodeException
    {
        public NotFoundException(string s) : base(404, s)
        {
        }
    }
}
