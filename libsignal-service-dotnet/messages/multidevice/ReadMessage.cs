using libsignalservice.push;

namespace libsignalservice.messages.multidevice
{
    public class ReadMessage
    {
        public SignalServiceAddress Sender { get; }
        public long Timestamp { get; }

        public ReadMessage(SignalServiceAddress sender, long timestamp)
        {
            Sender = sender;
            Timestamp = timestamp;
        }
    }
}
