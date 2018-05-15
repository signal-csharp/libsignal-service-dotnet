namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class ReadMessage
    {
        public string Sender { get; }
        public long Timestamp { get; }

        public ReadMessage(string sender, long timestamp)
        {
            Sender = sender;
            Timestamp = timestamp;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
