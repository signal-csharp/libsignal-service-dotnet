using System.Collections.Generic;
using libsignalservice.push;

namespace libsignalservice.messages.multidevice
{
    public class DeviceGroup
    {
        public byte[] Id { get; }
        public string? Name { get; }
        public List<SignalServiceAddress> Members { get; }
        public SignalServiceAttachmentStream? Avatar { get; }
        public bool Active { get; }
        public uint? ExpirationTimer { get; }
        public string? Color { get; }
        public bool Blocked { get; }

        public DeviceGroup(byte[] id, string? name, List<SignalServiceAddress> members,
            SignalServiceAttachmentStream? avatar,
            bool active, uint? expirationTimer,
            string? color, bool blocked)
        {
            Id = id;
            Name = name;
            Members = members;
            Avatar = avatar;
            Active = active;
            ExpirationTimer = expirationTimer;
            Color = color;
            Blocked = blocked;
        }
    }
}
