using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.messages
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalServiceReceiptMessage
    {
        public enum Type
        {
            UNKNOWN, DELIVERY, READ
        }

        public Type ReceiptType { get; set; }
        public List<ulong> Timestamps { get; set; }
        public long When { get; set; }
        public bool IsDeliveryReceipt() => ReceiptType == Type.DELIVERY;
        public bool IsReadReceipt() => ReceiptType == Type.READ;
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
