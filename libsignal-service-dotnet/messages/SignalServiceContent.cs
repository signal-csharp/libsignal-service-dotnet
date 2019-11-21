using libsignal_service_dotnet.messages.calls;
using libsignalservice.messages.multidevice;

namespace libsignalservice.messages
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalServiceContent
    {
        public string Sender { get; }
        public int SenderDevice { get; }
        public long Timestamp { get; }
        public bool NeedsReceipt { get; }

        public SignalServiceDataMessage? Message { get; set; }
        public SignalServiceSyncMessage? SynchronizeMessage { get; set; }
        public SignalServiceCallMessage? CallMessage { get; set; }
        public SignalServiceReceiptMessage? ReadMessage { get; set; }

        public SignalServiceContent(string sender, int senderDevice, long timestamp, bool needsReceipt)
        {
            Sender = sender;
            SenderDevice = senderDevice;
            Timestamp = timestamp;
            NeedsReceipt = needsReceipt;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
