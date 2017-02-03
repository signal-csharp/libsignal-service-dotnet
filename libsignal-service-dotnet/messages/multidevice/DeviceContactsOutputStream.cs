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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace libsignalservice.messages.multidevice
{
    public class DeviceContactsOutputStream : ChunkedOutputStream
    {

        public DeviceContactsOutputStream(Stream output)
            : base(output)
        {
        }

        public void write(DeviceContact contact)// throws IOException
        {
            writeContactDetails(contact);
            writeAvatarImage(contact);
        }

        public void close()// throws IOException
        {
            //output.close();
        }

        private void writeAvatarImage(DeviceContact contact)// throws IOException
        {
            if (contact.getAvatar().HasValue)
            {
                //writeStream(contact.getAvatar().get().getInputStream());
            }
        }

        private void writeContactDetails(DeviceContact contact)// throws IOException
        {
            //SignalServiceProtos.ContactDetails.Builder contactDetails = SignalServiceProtos.ContactDetails.CreateBuilder();
            //contactDetails.SetNumber(contact.getNumber());

            /*if (contact.getName().HasValue)
            {
                contactDetails.SetName(contact.getName().ForceGetValue());
            }

            if (contact.getAvatar().HasValue)
            {
                SignalServiceProtos.ContactDetails.Avatar.Builder avatarBuilder = ContactDetails.Avatar.CreateBuilder();
                avatarBuilder.setContentType(contact.getAvatar().ForceGetValue().getContentType());
                avatarBuilder.setLength((int)contact.getAvatar().ForceGetValue().getLength());
                contactDetails.SetAvatar(avatarBuilder);
            }

            byte[] serializedContactDetails = contactDetails.Build().ToByteArray();

            writeVarint32(serializedContactDetails.Length);
            output.write(serializedContactDetails);*/
            throw new NotImplementedException();
        }

    }
}
