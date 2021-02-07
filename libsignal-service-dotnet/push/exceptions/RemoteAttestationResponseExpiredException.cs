namespace libsignalservice.push.exceptions
{
    public class RemoteAttestationResponseExpiredException : NonSuccessfulResponseCodeException
    {
        public RemoteAttestationResponseExpiredException(string message) : base(409, message)
        {
        }
    }
}
