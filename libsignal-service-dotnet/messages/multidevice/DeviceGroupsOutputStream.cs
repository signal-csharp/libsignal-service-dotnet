using System.Collections.Generic;
using System.IO;
using Google.Protobuf;
using libsignalservice.push;

namespace libsignalservice.messages.multidevice
{
    internal class DeviceGroupsOutputStream : ChunkedOutputStream
    {
        public DeviceGroupsOutputStream(Stream output)
            : base(output)
        {
        }

        public void Write(DeviceGroup group)
        {
            WriteGroupDetails(group);
            WriteAvatarImage(group);
        }

        public void Close()
        {
            output.Dispose();
        }

        private void WriteAvatarImage(DeviceGroup contact)
        {
            if (contact.Avatar != null)
            {
                WriteStream(contact.Avatar.InputStream);
            }
        }

        private void WriteGroupDetails(DeviceGroup group)
        {
            GroupDetails groupDetails = new GroupDetails();
            groupDetails.Id = ByteString.CopyFrom(group.Id);

            if (group.Name != null)
            {
                groupDetails.Name = group.Name;
            }

            if (group.Avatar != null)
            {
                GroupDetails.Types.Avatar avatarBuilder = new GroupDetails.Types.Avatar();
                avatarBuilder.ContentType = group.Avatar.ContentType;
                avatarBuilder.Length = (uint)group.Avatar.Length;
                groupDetails.Avatar = avatarBuilder;
            }

            if (group.ExpirationTimer.HasValue)
            {
                groupDetails.ExpireTimer = group.ExpirationTimer.Value;
            }

            if (group.Color != null)
            {
                groupDetails.Color = group.Color;
            }

            List<GroupDetails.Types.Member> members = new List<GroupDetails.Types.Member>(group.Members.Count);

            foreach (SignalServiceAddress address in group.Members)
            {
                GroupDetails.Types.Member builder = new GroupDetails.Types.Member();

                if (address.Uuid.HasValue)
                {
                    builder.Uuid = address.Uuid.Value.ToString();
                }

                if (address.GetNumber() != null)
                {
                    builder.E164 = address.GetNumber();
                }

                members.Add(builder);
            }

            groupDetails.Members.AddRange(members);
            groupDetails.Active = group.Active;
            groupDetails.Blocked = group.Blocked;

            byte[] serializedContactDetails = groupDetails.ToByteArray();

            WriteVarint32(serializedContactDetails.Length);
            output.Write(serializedContactDetails, 0, serializedContactDetails.Length);
        }
    }
}
