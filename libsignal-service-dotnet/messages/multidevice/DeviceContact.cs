using libsignalservice.push;

namespace libsignalservice.messages.multidevice
{
    public class DeviceContact
    {
        public SignalServiceAddress Address { get; }
        public string? Name { get; }
        public SignalServiceAttachmentStream? Avatar { get; }
        public string? Color { get; }
        public VerifiedMessage? Verified { get; }
        public byte[]? ProfileKey { get; }
        public bool Blocked { get; }
        public uint? ExpirationTimer { get; }

        public DeviceContact(SignalServiceAddress address, string? name,
            SignalServiceAttachmentStream? avatar,
            string? color,
            VerifiedMessage? verified,
            byte[]? profileKey,
            bool blocked,
            uint? expirationTimer)
        {
            Address = address;
            Name = name;
            Avatar = avatar;
            Color = color;
            Verified = verified;
            ProfileKey = profileKey;
            Blocked = blocked;
            ExpirationTimer = expirationTimer;
        }
    }
}
