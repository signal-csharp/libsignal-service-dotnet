using libsignal;
using libsignalservice.push;

namespace libsignalservice.messages.multidevice
{
    public class VerifiedMessage
    {
        public enum VerifiedState
        {
            Default,
            Verified,
            Unverified
        }

        public SignalServiceAddress Destination { get; }

        public IdentityKey IdentityKey { get; }

        public VerifiedState Verified { get; }

        public long Timestamp { get; }

        public VerifiedMessage(SignalServiceAddress destination, IdentityKey identityKey, VerifiedState verified, long timestamp)
        {
            Destination = destination;
            IdentityKey = identityKey;
            Verified = verified;
            Timestamp = timestamp;
        }
    }
}
