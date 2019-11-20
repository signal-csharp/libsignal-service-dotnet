using System;
using System.Collections.Generic;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class DeviceGroup
    {
        public byte[] Id { get; }
        public string? Name { get; }
        public IList<string> Members { get; }
        public SignalServiceAttachmentStream? Avatar { get; }
        public bool Active { get; }
        public uint? ExpirationTimer { get; }
        public string? Color { get; }

        public DeviceGroup(byte[] id, string? name, IList<string> members, SignalServiceAttachmentStream? avatar, bool active, uint? expirationTimer, string? color)
        {
            Id = id;
            Name = name;
            Members = members;
            Avatar = avatar;
            Active = active;
            ExpirationTimer = expirationTimer;
            Color = color;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
