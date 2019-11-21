using System;

namespace libsignalmetadatadotnet
{
    public abstract class ProtocolException : Exception
    {
        public string Sender { get; set; }
        public int SenderDevice { get; set; }

        public ProtocolException(Exception inner, string sender, int senderDevice) : base(inner.Message, inner)
        {
            Sender = sender;
            SenderDevice = senderDevice;
        }
    }
}
