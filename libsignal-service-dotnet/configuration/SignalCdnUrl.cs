using libsignalservice.push;

namespace libsignalservice.configuration
{
    public class SignalCdnUrl : SignalUrl
    {
        public SignalCdnUrl(string url) : base(url)
        {
        }

        public SignalCdnUrl(string url, string? hostHeader) : base(url, hostHeader)
        {
        }
    }
}
