using libsignal;
using libsignalservice.push;
using libsignalservice.util;
using System;
using System.IO;
using static libsignalservice.messages.multidevice.VerifiedMessage;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class DeviceContactsInputStream : ChunkedInputStream
    {
        public DeviceContactsInputStream(Stream input) : base(input) { }

        public DeviceContact Read()// throws IOException
        {
            int detailsLength = ReadRawVarint32();
            if (detailsLength == -1)
            {
                return null;
            }
            byte[] detailsSerialized = new byte[(int)detailsLength];
            Util.ReadFully(InputStream, detailsSerialized);

            var details = ContactDetails.Parser.ParseFrom(detailsSerialized);
            string number = details.Number;
            string name = details.Name;
            SignalServiceAttachmentStream avatar = null;
            string color = details.ColorOneofCase == ContactDetails.ColorOneofOneofCase.Color ? details.Color : null;
            VerifiedMessage verified = null;
            byte[] profileKey = null;
            bool blocked = false;
            uint? expireTimer = null;

            if (details.AvatarOneofCase == ContactDetails.AvatarOneofOneofCase.Avatar)
            {
                long avatarLength = details.Avatar.Length;
                Stream avatarStream = new LimitedInputStream(InputStream, avatarLength);
                String avatarContentType = details.Avatar.ContentType;
                avatar = new SignalServiceAttachmentStream(avatarStream, avatarContentType, avatarLength, null, false, null);
            }

            if (details.VerifiedOneofCase == ContactDetails.VerifiedOneofOneofCase.Verified)
            {
                string destination = details.Verified.Destination;
                IdentityKey identityKey = new IdentityKey(details.Verified.IdentityKey.ToByteArray(), 0);

                VerifiedState state;
                switch (details.Verified.State)
                {
                    case Verified.Types.State.Verified:
                        state = VerifiedState.Verified;
                        break;
                    case Verified.Types.State.Unverified:
                        state = VerifiedState.Unverified;
                        break;
                    case Verified.Types.State.Default:
                        state = VerifiedState.Default;
                        break;
                    default:
                        throw new InvalidMessageException("Unknown state: " + details.Verified.State);
                }

                verified = new VerifiedMessage(destination, identityKey, state, Util.CurrentTimeMillis());
            }

            if (details.ProfileKeyOneofCase == ContactDetails.ProfileKeyOneofOneofCase.ProfileKey)
            {
                profileKey = details.ProfileKey.ToByteArray();
            }

            if (details.ExpireTimerOneofCase == ContactDetails.ExpireTimerOneofOneofCase.ExpireTimer && details.ExpireTimer > 0)
            {
                expireTimer = details.ExpireTimer;
            }

            return new DeviceContact(number, name, avatar, color, verified, profileKey, blocked, expireTimer);
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
