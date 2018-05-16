using System;
using System.IO;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
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
            if (contact.Avatar != null)
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
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
