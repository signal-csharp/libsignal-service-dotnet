using libsignal_service_dotnet.messages.calls;
using libsignalservice.messages.multidevice;

namespace libsignalservice.messages
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalServiceContent
    {
        public SignalServiceDataMessage Message { get; set; }
        public SignalServiceSyncMessage SynchronizeMessage { get; set; }
        public SignalServiceCallMessage CallMessage { get; set; }
        public SignalServiceReceiptMessage ReadMessage { get; set; }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
