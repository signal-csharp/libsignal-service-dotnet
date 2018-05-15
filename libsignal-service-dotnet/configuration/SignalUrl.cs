using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.configuration
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalUrl
    {
        public string Url { get; }
        public string HostHeader { get; }

        public SignalUrl(string url) : this(url, null) { }

        public SignalUrl(string url, string hostHeader)
        {
            Url = url;
            HostHeader = hostHeader;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
