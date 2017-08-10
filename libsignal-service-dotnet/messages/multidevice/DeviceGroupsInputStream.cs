using libsignalservice.push;
using libsignalservice.util;
using Strilanc.Value;

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

using System.Collections.Generic;
using System.IO;

namespace libsignalservice.messages.multidevice
{
    public class DeviceGroupsInputStream : ChunkedInputStream
    {
        public DeviceGroupsInputStream(Stream input)
        : base(input)
        {
        }

        public DeviceGroup read()// throws IOException
        {
            long detailsLength = readRawVarint32();
            byte[] detailsSerialized = new byte[(int)detailsLength];
            Util.readFully(input, detailsSerialized);

            GroupDetails details = GroupDetails.Parser.ParseFrom(detailsSerialized);

            if (details.IdOneofCase == GroupDetails.IdOneofOneofCase.None)
            {
                throw new IOException("ID missing on group record!");
            }

            byte[] id = details.Id.ToByteArray();
            May<string> name = new May<string>(details.Name);
            IList<string> members = details.Members;
            May<SignalServiceAttachmentStream> avatar = May<SignalServiceAttachmentStream>.NoValue;
            bool active = details.Active;

            if (details.AvatarOneofCase == GroupDetails.AvatarOneofOneofCase.Avatar)
            {
                long avatarLength = details.Avatar.Length;
                Stream avatarStream = new ChunkedInputStream.LimitedInputStream(avatarLength);
                string avatarContentType = details.Avatar.ContentType;

                avatar = new May<SignalServiceAttachmentStream>(new SignalServiceAttachmentStream(avatarStream, avatarContentType, avatarLength, null, null));
            }

            return new DeviceGroup(id, name, members, avatar, active);
        }
    }
}
