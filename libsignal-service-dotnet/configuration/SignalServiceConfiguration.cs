namespace libsignalservice.configuration
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalServiceConfiguration
    {
        public SignalServiceUrl[] SignalServiceUrls { get; }
        public SignalCdnUrl[] SignalCdnUrls { get; }

        public SignalServiceConfiguration(SignalServiceUrl[] signalServiceUrls, SignalCdnUrl[] signalCdnUrls)
        {
            SignalServiceUrls = signalServiceUrls;
            SignalCdnUrls = signalCdnUrls;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
