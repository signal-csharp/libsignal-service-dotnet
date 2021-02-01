using libsignalservice.push;

namespace libsignalservice.configuration
{
    public class SignalContactDiscoveryUrl : SignalUrl
    {
        public SignalContactDiscoveryUrl(string url) : base(url)
        {
        }

        public SignalContactDiscoveryUrl(string url, string? hostHeader) : base(url, hostHeader)
        {
        }
    }
}
