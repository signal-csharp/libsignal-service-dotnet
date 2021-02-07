namespace libsignalservice.push.exceptions
{
    /// <summary>
    /// Indicates the server has rejected the request and we should stop retrying.
    /// </summary>
    public class ServerRejectedException : NonSuccessfulResponseCodeException
    {
        public ServerRejectedException() : base(508)
        {
        }
    }
}
