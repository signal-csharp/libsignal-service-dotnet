using libsignal_service_dotnet.messages.calls;
using libsignalservice.messages.multidevice;

namespace libsignalservice.messages
{
    public class SignalServiceContent
    {
        public string Sender { get; }
        public int SenderDevice { get; }
        public long Timestamp { get; }
        public bool NeedsReceipt { get; }

        public SignalServiceDataMessage? Message { get; }
        public SignalServiceSyncMessage? SynchronizeMessage { get; }
        public SignalServiceCallMessage? CallMessage { get; }
        public SignalServiceReceiptMessage? ReadMessage { get; }
        public SignalServiceTypingMessage? TypingMessage { get; }

        public SignalServiceContent(SignalServiceDataMessage message, string sender, int senderDevice, long timestamp, bool needsReceipt)
        {
            Sender = sender;
            SenderDevice = senderDevice;
            Timestamp = timestamp;
            NeedsReceipt = needsReceipt;

            Message = message;
            SynchronizeMessage = null;
            CallMessage = null;
            ReadMessage = null;
            TypingMessage = null;
        }

        public SignalServiceContent(SignalServiceSyncMessage synchronizeMessage, string sender, int senderDevice, long timestamp, bool needsReceipt)
        {
            Sender = sender;
            SenderDevice = senderDevice;
            Timestamp = timestamp;
            NeedsReceipt = needsReceipt;

            Message = null;
            SynchronizeMessage = synchronizeMessage;
            CallMessage = null;
            ReadMessage = null;
            TypingMessage = null;
        }

        public SignalServiceContent(SignalServiceCallMessage callMessage, string sender, int senderDevice, long timestamp, bool needsReceipt)
        {
            Sender = sender;
            SenderDevice = senderDevice;
            Timestamp = timestamp;
            NeedsReceipt = needsReceipt;

            Message = null;
            SynchronizeMessage = null;
            CallMessage = callMessage;
            ReadMessage = null;
            TypingMessage = null;
        }

        public SignalServiceContent(SignalServiceReceiptMessage receiptMessage, string sender, int senderDevice, long timestamp, bool needsReceipt)
        {
            Sender = sender;
            SenderDevice = senderDevice;
            Timestamp = timestamp;
            NeedsReceipt = needsReceipt;

            Message = null;
            SynchronizeMessage = null;
            CallMessage = null;
            ReadMessage = receiptMessage;
            TypingMessage = null;
        }

        public SignalServiceContent(SignalServiceTypingMessage typingMessage, string sender, int senderDevice, long timestamp, bool needsReceipt)
        {
            Sender = sender;
            SenderDevice = senderDevice;
            Timestamp = timestamp;
            NeedsReceipt = needsReceipt;

            Message = null;
            SynchronizeMessage = null;
            CallMessage = null;
            ReadMessage = null;
            TypingMessage = typingMessage;
        }
    }
}
