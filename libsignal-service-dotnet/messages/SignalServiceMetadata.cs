using libsignalservice.push;

namespace libsignalservice.messages
{
    public class SignalServiceMetadata
    {
        public SignalServiceAddress Sender { get; }
        public int SenderDevice { get; }
        public long Timestamp { get; }
        public bool NeedsReceipt { get; }

        public SignalServiceMetadata(SignalServiceAddress sender, int senderDevice, long timestamp, bool needsReceipt)
        {
            Sender = sender;
            SenderDevice = senderDevice;
            Timestamp = timestamp;
            NeedsReceipt = needsReceipt;
        }
    }
}
