namespace libsignalservice.push.exceptions
{
    public class RemoteAttestationResponseExpiredException : NonSuccessfulResponseCodeException
    {
        public RemoteAttestationResponseExpiredException(string message) : base(message)
        {
        }
    }
}
