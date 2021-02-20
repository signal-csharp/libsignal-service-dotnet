using System.Collections.Generic;
using System.IO;
using libsignalservice.push;
using libsignalservice.util;

namespace libsignalservice.messages.multidevice
{
    public class DeviceGroupsInputStream : ChunkedInputStream
    {
        public DeviceGroupsInputStream(Stream input): base(input) { }

        public DeviceGroup? Read()
        {
            int detailsLength = ReadRawVarint32();
            if (detailsLength == -1)
            {
                return null;
            }
            byte[] detailsSerialized = new byte[detailsLength];
            Util.ReadFully(InputStream, detailsSerialized);

            GroupDetails details = GroupDetails.Parser.ParseFrom(detailsSerialized);
            byte[] id = details.Id.ToByteArray();
            string? name = details.HasName ? details.Name : null;
            List<string> members = new List<string>();
            members.AddRange(details.Members);
            SignalServiceAttachmentStream? avatar = null;
            bool active = details.Active;
            uint? expirationTimer = null;
            string? color = details.HasColor ? details.Color : null;
            bool blocked = details.Blocked;

            if (details.Avatar != null)
            {
                long avatarLength = details.Avatar.Length;
                Stream avatarStream = new LimitedInputStream(InputStream, avatarLength);
                string avatarContentType = details.Avatar.ContentType;
                avatar = new SignalServiceAttachmentStream(avatarStream, avatarContentType, avatarLength, null, false, null);
            }

            if (details.HasExpireTimer && details.ExpireTimer > 0)
            {
                expirationTimer = details.ExpireTimer;
            }

            return new DeviceGroup(id, name, members, avatar, active, expirationTimer, color, blocked);
        }
    }
}
