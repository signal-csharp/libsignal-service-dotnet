namespace libsignalservice.messages.multidevice
{
    public class MessageTimerReadMessage
    {
        public string Sender { get; }
        public long Timestamp { get; }

        public MessageTimerReadMessage(string sender, long timestamp)
        {
            Sender = sender;
            Timestamp = timestamp;
        }
    }
}
