using libsignal;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class VerifiedMessage
    {
        public enum VerifiedState
        {
            Default,
            Verified,
            Unverified
        }

        public string Destination { get; private set; }

        public IdentityKey IdentityKey { get; private set; }

        public VerifiedState Verified { get; private set; }

        public long Timestamp { get; private set; }

        public VerifiedMessage(string destination, IdentityKey identityKey, VerifiedState verified, long timestamp)
        {
            Destination = destination;
            IdentityKey = identityKey;
            Verified = verified;
            Timestamp = timestamp;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
