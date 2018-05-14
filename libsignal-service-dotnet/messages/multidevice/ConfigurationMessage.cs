using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class ConfigurationMessage
    {
        public bool? ReadReceipts { get; }
        public ConfigurationMessage(bool? readReceipts)
        {
            ReadReceipts = readReceipts;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
