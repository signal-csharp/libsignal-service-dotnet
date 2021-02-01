using libsignalservice.push;

namespace libsignalservice.configuration
{
    public class SignalUrl
    {
        public string Url { get; }
        public string? HostHeader { get; }

        public SignalUrl(string url) : this(url, null)
        {
        }

        public SignalUrl(string url, string? hostHeader)
        {
            Url = url;
            HostHeader = hostHeader;
        }
    }
}
