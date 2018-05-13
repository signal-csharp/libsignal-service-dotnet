using libsignalservice.push;
using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.configuration
{
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
}
