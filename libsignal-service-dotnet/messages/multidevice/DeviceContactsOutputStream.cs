using System.IO;
using Google.Protobuf;
using libsignalservice.push;

namespace libsignalservice.messages.multidevice
{
    public class DeviceContactsOutputStream : ChunkedOutputStream
    {
        public DeviceContactsOutputStream(Stream output)
            : base(output)
        {
        }

        public void Write(DeviceContact contact)
        {
            WriteContactDetails(contact);
            WriteAvatarImage(contact);
        }

        public void Close()
        {
            output.Dispose();
        }

        private void WriteAvatarImage(DeviceContact contact)
        {
            if (contact.Avatar != null)
            {
                WriteStream(contact.Avatar.InputStream);
            }
        }

        private void WriteContactDetails(DeviceContact contact)
        {
            ContactDetails contactDetails = new ContactDetails();

            if (contact.Address.Uuid.HasValue)
            {
                contactDetails.Uuid = contact.Address.Uuid.Value.ToString();
            }

            if (contact.Address.GetNumber() != null)
            {
                contactDetails.Number = contact.Address.GetNumber();
            }

            if (contact.Name != null)
            {
                contactDetails.Name = contact.Name;
            }

            if (contact.Avatar != null)
            {
                ContactDetails.Types.Avatar avatarBuilder = new ContactDetails.Types.Avatar();
                avatarBuilder.ContentType = contact.Avatar.ContentType;
                avatarBuilder.Length = (uint)contact.Avatar.Length;
                contactDetails.Avatar = avatarBuilder;
            }

            if (contact.Color != null)
            {
                contactDetails.Color = contact.Color;
            }

            if (contact.Verified != null)
            {
                Verified.Types.State state;

                switch (contact.Verified.Verified)
                {
                    case VerifiedMessage.VerifiedState.Verified: state = Verified.Types.State.Verified; break;
                    case VerifiedMessage.VerifiedState.Unverified: state = Verified.Types.State.Unverified; break;
                    default: state = Verified.Types.State.Default; break;
                }

                Verified verifiedBuilder = new Verified()
                {
                    IdentityKey = ByteString.CopyFrom(contact.Verified.IdentityKey.serialize()),
                    State = state
                };

                if (contact.Verified.Destination.Uuid.HasValue)
                {
                    verifiedBuilder.DestinationUuid = contact.Verified.Destination.Uuid.Value.ToString();
                }

                if (contact.Verified.Destination.GetNumber() != null)
                {
                    verifiedBuilder.DestinationE164 = contact.Verified.Destination.GetNumber();
                }

                contactDetails.Verified = verifiedBuilder;
            }

            if (contact.ProfileKey != null)
            {
                contactDetails.ProfileKey = ByteString.CopyFrom(contact.ProfileKey);
            }

            if (contact.ExpirationTimer.HasValue)
            {
                contactDetails.ExpireTimer = contact.ExpirationTimer.Value;
            }

            contactDetails.Blocked = contact.Blocked;

            byte[] serializedContactDetails = contactDetails.ToByteArray();

            WriteVarint32(serializedContactDetails.Length);
            output.Write(serializedContactDetails, 0, serializedContactDetails.Length);
        }
    }
}
