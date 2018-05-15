namespace libsignalservice.configuration
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalServiceUrl : SignalUrl
    {
        public SignalServiceUrl(string url): this(url, null) {}

        public SignalServiceUrl(string url, string hostHeader) : base(url, hostHeader) {}
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
