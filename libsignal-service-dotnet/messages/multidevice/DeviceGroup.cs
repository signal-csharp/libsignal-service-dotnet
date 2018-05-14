/**
 * Copyright (C) 2017 smndtrl, golf1052
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using Strilanc.Value;
using System;
using System.Collections.Generic;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class DeviceGroup
    {
        public byte[] Id { get; }
        public String Name { get; }
        public IList<String> Members { get; }
        public SignalServiceAttachmentStream Avatar { get; }
        public bool Active { get; }
        public int? ExpirationTimer { get; }

        public DeviceGroup(byte[] id, string name, IList<string> members, SignalServiceAttachmentStream avatar, bool active, int? expirationTimer)
        {
            Id = id;
            Name = name;
            Members = members;
            Avatar = avatar;
            Active = active;
            ExpirationTimer = expirationTimer;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
