namespace libsignalservice.push.exceptions
{
    public class RangeException : NonSuccessfulResponseCodeException
    {
        public RangeException(long requested) : base(416, $"Range request out of bounds {requested}")
        {
        }
    }
}
