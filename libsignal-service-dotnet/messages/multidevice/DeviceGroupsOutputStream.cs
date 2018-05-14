using Google.Protobuf;
using libsignalservice.push;

using System;
using System.IO;

namespace libsignalservice.messages.multidevice
{
    internal class DeviceGroupsOutputStream : ChunkedOutputStream
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
                throw new NotImplementedException();
                //contact.getAvatar().Match(e => e, () => { throw new Exception(); }).InputStream;
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
                avatarBuilder.Length = (uint)avatar.Length;
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
