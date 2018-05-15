using System;
using System.IO;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
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
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
