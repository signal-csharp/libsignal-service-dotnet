using libsignalservice.push;

namespace libsignalservice.messages.multidevice
{
    public class ViewOnceOpenMessage
    {
        public SignalServiceAddress Sender { get; }
        public long Timestamp { get; }

        public ViewOnceOpenMessage(SignalServiceAddress sender, long timestamp)
        {
            Sender = sender;
            Timestamp = timestamp;
        }
    }
}
