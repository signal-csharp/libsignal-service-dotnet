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
            WriteGroupDetails(group);
            writeAvatarImage(group);
        }

        public void close()
        {
            //output.close();
        }

        private void writeAvatarImage(DeviceGroup contact)
        {
            if (contact.Avatar != null)
            {
                throw new NotImplementedException();
                //contact.getAvatar().Match(e => e, () => { throw new Exception(); }).InputStream;
            }
        }

        private void WriteGroupDetails(DeviceGroup group)// throws IOException
        {
            GroupDetails groupDetails = new GroupDetails { };
            groupDetails.Id = ByteString.CopyFrom(group.Id);

            if (group.Name != null)
            {
                //groupDetails.Name = group.getName().Match(e => e, () => { throw new Exception(); });
            }

            if (group.Avatar != null)
            {
                //GroupDetails.Types.GroupAvatar avatarBuilder = new GroupDetails.Types.GroupAvatar { };
                //SignalServiceAttachmentStream avatar = group.getAvatar().Match(e => e, () => { throw new Exception(); });
                //avatarBuilder.ContentType = avatar.C;
                //avatarBuilder.Length = (uint)avatar.Length;
                //groupDetails.Avatar = avatarBuilder;
            }

            //if (group.ExpirationTimer

            groupDetails.Members.AddRange(group.Members);
            //groupDetails.Active = group.Active;

            byte[] serializedContactDetails = groupDetails.ToByteArray();

            writeVarint32(serializedContactDetails.Length);
            output.Write(serializedContactDetails, 0, serializedContactDetails.Length);
        }
    }
}
