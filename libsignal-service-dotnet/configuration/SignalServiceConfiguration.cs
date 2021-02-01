namespace libsignalservice.configuration
{
    public class SignalServiceConfiguration
    {
        public SignalServiceUrl[] SignalServiceUrls { get; }
        public SignalCdnUrl[] SignalCdnUrls { get; }
        public SignalContactDiscoveryUrl[] SignalContactDiscoveryUrls { get; }

        public SignalServiceConfiguration(SignalServiceUrl[] signalServiceUrls, SignalCdnUrl[] signalCdnUrls, SignalContactDiscoveryUrl[] signalContactDiscoveryUrls)
        {
            SignalServiceUrls = signalServiceUrls;
            SignalCdnUrls = signalCdnUrls;
            SignalContactDiscoveryUrls = signalContactDiscoveryUrls;
        }
    }
}
