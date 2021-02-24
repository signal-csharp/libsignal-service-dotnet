namespace libsignalservice.messages.multidevice
{
    public class StickerPackOperationMessage
    {
        public enum OperationType
        {
            Install,
            Remove
        }

        public byte[]? PackId { get; }
        public byte[]? PackKey { get; }
        public OperationType? Type { get; }

        public StickerPackOperationMessage(byte[]? packId, byte[]? packKey, OperationType? type)
        {
            PackId = packId;
            PackKey = packKey;
            Type = type;
        }
    }
}
