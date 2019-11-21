using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class ConfigurationMessage
    {
        public bool? ReadReceipts { get; }
        public bool? UnidentifiedDeliveryIndicators { get; }
        public ConfigurationMessage(bool? readReceipts, bool? unidentifiedDeliveryIndicators)
        {
            ReadReceipts = readReceipts;
            UnidentifiedDeliveryIndicators = unidentifiedDeliveryIndicators;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
