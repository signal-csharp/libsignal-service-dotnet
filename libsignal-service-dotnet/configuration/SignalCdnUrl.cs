using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.configuration
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalCdnUrl : SignalUrl
    {
        public SignalCdnUrl(string url) : base(url) { }

        public SignalCdnUrl(string url, string hostHeader) : base(url, hostHeader) { }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
