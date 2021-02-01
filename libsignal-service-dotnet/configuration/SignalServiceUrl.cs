using libsignalservice.push;

namespace libsignalservice.configuration
{
    public class SignalServiceUrl : SignalUrl
    {
        public SignalServiceUrl(string url) : base(url) {}

        public SignalServiceUrl(string url, string? hostHeader) : base(url, hostHeader) {}
    }
}
