using System;
using System.IO;
using libsignal;
using libsignalservice.push;
using libsignalservice.util;
using Microsoft.Extensions.Logging;
using static libsignalservice.messages.multidevice.VerifiedMessage;

namespace libsignalservice.messages.multidevice
{
    public class DeviceContactsInputStream : ChunkedInputStream
    {
        private readonly ILogger logger = LibsignalLogging.CreateLogger<DeviceContactsInputStream>();

        public DeviceContactsInputStream(Stream input) : base(input) { }

        public DeviceContact? Read()
        {
            int detailsLength = ReadRawVarint32();
            if (detailsLength == -1)
            {
                return null;
            }
            byte[] detailsSerialized = new byte[(int)detailsLength];
            Util.ReadFully(inputStream, detailsSerialized);

            var details = ContactDetails.Parser.ParseFrom(detailsSerialized);
            SignalServiceAddress address = new SignalServiceAddress(UuidUtil.ParseOrNull(details.Uuid), details.Number);
            string? name = details.Name;
            SignalServiceAttachmentStream? avatar = null;
            string? color = details.HasColor ? details.Color : null;
            VerifiedMessage? verified = null;
            byte[]? profileKey = null;
            bool blocked = false;
            uint? expireTimer = null;

            if (details.Avatar != null)
            {
                long avatarLength = details.Avatar.Length;
                Stream avatarStream = new LimitedInputStream(inputStream, avatarLength);
                string avatarContentType = details.Avatar.ContentType;
                avatar = new SignalServiceAttachmentStream(avatarStream, avatarContentType, avatarLength, null, false, null);
            }

            if (details.Verified != null)
            {
                try
                {
                    IdentityKey identityKey = new IdentityKey(details.Verified.IdentityKey.ToByteArray(), 0);
                    SignalServiceAddress destination = new SignalServiceAddress(UuidUtil.ParseOrNull(details.Verified.DestinationUuid),
                        details.Verified.DestinationE164);

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
                catch (Exception ex) when (ex is InvalidKeyException || ex is InvalidMessageException)
                {
                    logger.LogWarning(new EventId(), ex, "");
                    verified = null;
                }
            }

            if (details.HasProfileKey)
            {
                profileKey = details.ProfileKey.ToByteArray();
            }

            if (details.HasExpireTimer && details.ExpireTimer > 0)
            {
                expireTimer = details.ExpireTimer;
            }

            return new DeviceContact(address, name, avatar, color, verified, profileKey, blocked, expireTimer);
        }
    }
}
