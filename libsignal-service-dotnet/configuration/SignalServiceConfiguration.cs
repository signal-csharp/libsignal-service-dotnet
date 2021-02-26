namespace libsignalservice.configuration
{
    public class SignalServiceConfiguration
    {
        public SignalServiceUrl[] SignalServiceUrls { get; }
        public SignalCdnUrl[] SignalCdnUrls { get; }
        public SignalCdnUrl[] SignalCdn2Urls { get; }
        public SignalContactDiscoveryUrl[] SignalContactDiscoveryUrls { get; }

        public SignalServiceConfiguration(SignalServiceUrl[] signalServiceUrls,
            SignalCdnUrl[] signalCdnUrls,
            SignalCdnUrl[] signalCdn2Urls,
            SignalContactDiscoveryUrl[] signalContactDiscoveryUrls)
        {
            SignalServiceUrls = signalServiceUrls;
            SignalCdnUrls = signalCdnUrls;
            SignalCdn2Urls = signalCdn2Urls;
            SignalContactDiscoveryUrls = signalContactDiscoveryUrls;
        }
    }
}
