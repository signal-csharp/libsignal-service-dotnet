using Google.Protobuf;
using libsignalservice.push;

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

using System;
using System.IO;

namespace libsignalservice.messages.multidevice
{
    public class DeviceGroupsOutputStream : ChunkedOutputStream
    {
        public DeviceGroupsOutputStream(Stream output)
            : base(output)
        {
        }

        public void write(DeviceGroup group)
        {
            writeGroupDetails(group);
            writeAvatarImage(group);
        }

        public void close()
        {
            //output.close();
        }

        private void writeAvatarImage(DeviceGroup contact)
        {
            if (contact.getAvatar().HasValue)
            {
                contact.getAvatar().Match(e => e, () => { throw new Exception(); }).getInputStream();
            }
        }

        private void writeGroupDetails(DeviceGroup group)// throws IOException
        {
            GroupDetails groupDetails = new GroupDetails { };
            groupDetails.Id = ByteString.CopyFrom(group.getId());

            if (group.getName().HasValue)
            {
                groupDetails.Name = group.getName().Match(e => e, () => { throw new Exception(); });
            }

            if (group.getAvatar().HasValue)
            {
                GroupDetails.Types.Avatar avatarBuilder = new GroupDetails.Types.Avatar { };
                SignalServiceAttachmentStream avatar = group.getAvatar().Match(e => e, () => { throw new Exception(); });
                avatarBuilder.ContentType = avatar.getContentType();
                avatarBuilder.Length = (uint)avatar.getLength();
                groupDetails.Avatar = avatarBuilder;
            }

            groupDetails.Members.AddRange(group.getMembers());
            groupDetails.Active = group.isActive();

            byte[] serializedContactDetails = groupDetails.ToByteArray();

            writeVarint32(serializedContactDetails.Length);
            output.Write(serializedContactDetails, 0, serializedContactDetails.Length);
        }
    }
}
