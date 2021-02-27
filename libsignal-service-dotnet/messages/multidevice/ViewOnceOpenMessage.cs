namespace libsignalservice.messages.multidevice
{
    public class ViewOnceOpenMessage
    {
        public string Sender { get; }
        public long Timestamp { get; }

        public ViewOnceOpenMessage(string sender, long timestamp)
        {
            Sender = sender;
            Timestamp = timestamp;
        }
    }
}
