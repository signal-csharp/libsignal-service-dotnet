namespace libsignalservice.messages.multidevice
{
    public class ConfigurationMessage
    {
        public bool? ReadReceipts { get; }
        public bool? UnidentifiedDeliveryIndicators { get; }
        public bool? TypingIndicators { get; }

        public bool? LinkPreviews { get; }

        public ConfigurationMessage(bool? readReceipts,
            bool? unidentifiedDeliveryIndicators,
            bool? typingIndicators,
            bool? linkPreviews)
        {
            ReadReceipts = readReceipts;
            UnidentifiedDeliveryIndicators = unidentifiedDeliveryIndicators;
            TypingIndicators = typingIndicators;
            LinkPreviews = linkPreviews;
        }
    }
}
