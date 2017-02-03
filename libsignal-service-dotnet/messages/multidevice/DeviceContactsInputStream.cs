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

using libsignalservice.push;
using libsignalservice.util;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace libsignalservice.messages.multidevice
{
    public class DeviceContactsInputStream : ChunkedInputStream
    {

        public DeviceContactsInputStream(Stream input)
        : base(input)
        {
        }

        public DeviceContact read()// throws IOException
        {
            /*long detailsLength = readRawVarint32();
            byte[] detailsSerialized = new byte[(int)detailsLength];
            Util.readFully(input, detailsSerialized);

            SignalServiceProtos.ContactDetails details = SignalServiceProtos.ContactDetails.ParseFrom(detailsSerialized);
            String number = details.Number;
            May<String> name = details.Name == null ? May<string>.NoValue : new May<string>(details.Name);
            May<TextSecureAttachmentStream> avatar = May<TextSecureAttachmentStream>.NoValue;

            if (details.HasAvatar)
            {
                long avatarLength = details.Avatar.Length;
                IInputStream avatarStream = new LimitedInputStream(input, avatarLength);
                String avatarContentType = details.Avatar.ContentType;

                avatar = new May<TextSecureAttachmentStream>(new TextSecureAttachmentStream(avatarStream, avatarContentType, avatarLength));
            }

            return new DeviceContact(number, name, avatar);*/
            throw new NotImplementedException();
        }

    }
}
