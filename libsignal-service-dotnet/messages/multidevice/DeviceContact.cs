namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class DeviceContact
    {
        public string Number { get; }
        public string Name { get; }
        public SignalServiceAttachmentStream Avatar { get; }
        public string Color { get; }
        public VerifiedMessage Verified { get; }
        public byte[] ProfileKey { get; }
        public bool Blocked { get; }
        public uint? ExpirationTimer { get; }

        public DeviceContact(string number, string name, SignalServiceAttachmentStream avatar, string color, VerifiedMessage verified, byte[] profileKey, bool blocked, uint? expirationTimer)
        {
            Number = number;
            Name = name;
            Avatar = avatar;
            Color = color;
            Verified = verified;
            ProfileKey = profileKey;
            Blocked = blocked;
            ExpirationTimer = expirationTimer;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
