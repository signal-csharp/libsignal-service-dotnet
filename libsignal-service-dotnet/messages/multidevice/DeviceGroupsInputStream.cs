using libsignalservice.push;
using libsignalservice.util;
using System.Collections.Generic;
using System.IO;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class DeviceGroupsInputStream : ChunkedInputStream
    {
        public DeviceGroupsInputStream(Stream input): base(input) { }

        public DeviceGroup Read()
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
            string name = details.Name;
            List<string> members = new List<string>();
            members.AddRange(details.Members);
            SignalServiceAttachmentStream avatar = null;
            bool active = details.Active;
            uint? expirationTimer = null;

            if (details.AvatarOneofCase == GroupDetails.AvatarOneofOneofCase.Avatar)
            {
                long avatarLength = details.Avatar.Length;
                Stream avatarStream = new LimitedInputStream(InputStream, avatarLength);
                string avatarContentType = details.Avatar.ContentType;
                avatar = new SignalServiceAttachmentStream(avatarStream, avatarContentType, avatarLength, null, false, null);
            }

            if (details.ExpireTimerOneofCase == GroupDetails.ExpireTimerOneofOneofCase.ExpireTimer)
            {
                expirationTimer = details.ExpireTimer;
            }

            return new DeviceGroup(id, name, members, avatar, active, expirationTimer);
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
