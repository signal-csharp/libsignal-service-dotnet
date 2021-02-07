namespace libsignalservice.push.exceptions
{
    public class ConflictException : NonSuccessfulResponseCodeException
    {
        public ConflictException() : base(409, "Conflict")
        {
        }
    }
}
