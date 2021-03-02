using System.Collections.Generic;
using System.IO;
using System.Linq;
using libsignalservice.push;
using libsignalservice.util;

namespace libsignalservice.messages.multidevice
{
    public class DeviceGroupsInputStream : ChunkedInputStream
    {
        public DeviceGroupsInputStream(Stream input): base(input) { }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public DeviceGroup? Read()
        {
            int detailsLength = ReadRawVarint32();
            if (detailsLength == -1)
            {
                return null;
            }
            byte[] detailsSerialized = new byte[detailsLength];
            Util.ReadFully(inputStream, detailsSerialized);

            GroupDetails details = GroupDetails.Parser.ParseFrom(detailsSerialized);

            if (!details.HasId)
            {
                throw new IOException("ID missing on group record!");
            }

            byte[] id = details.Id.ToByteArray();
            string? name = details.HasName ? details.Name : null;
            List<GroupDetails.Types.Member> members = details.Members.ToList();
            SignalServiceAttachmentStream? avatar = null;
            bool active = details.Active;
            uint? expirationTimer = null;
            string? color = details.HasColor ? details.Color : null;
            bool blocked = details.Blocked;

            if (details.Avatar != null)
            {
                long avatarLength = details.Avatar.Length;
                Stream avatarStream = new LimitedInputStream(inputStream, avatarLength);
                string avatarContentType = details.Avatar.ContentType;
                avatar = new SignalServiceAttachmentStream(avatarStream, avatarContentType, avatarLength, null, false, null);
            }

            if (details.HasExpireTimer && details.ExpireTimer > 0)
            {
                expirationTimer = details.ExpireTimer;
            }

            List<SignalServiceAddress> addressMembers = new List<SignalServiceAddress>(members.Count);
            foreach (GroupDetails.Types.Member member in members)
            {
                addressMembers.Add(new SignalServiceAddress(UuidUtil.ParseOrNull(member.Uuid), member.E164));
            }

            return new DeviceGroup(id, name, addressMembers, avatar, active, expirationTimer, color, blocked);
        }
    }
}
