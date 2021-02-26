namespace libsignalservice.push
{
    /// <summary>
    /// A class representing a message destination or origin.
    /// </summary>
    public class SignalServiceAddress
    {
        // TODO: FINISH UUID CHANGES
        public static readonly uint DEFAULT_DEVICE_ID = 1;

        public string E164number { get; }
        public string? Relay { get; }

        /// <summary>
        /// Construct a PushAddress.
        /// </summary>
        /// <param name="e164number">The Signal Service username of this destination (eg e164 representation of a phone number).</param>
        /// <param name="relay">The Signal Service federated server this user is registered with (if not your own server).</param>
        public SignalServiceAddress(string e164number, string? relay)
        {
            E164number = e164number;
            Relay = relay;
        }

        public SignalServiceAddress(string e164number)
        {
            E164number = e164number;
        }

        public string GetIdentifier()
        {
            return E164number;
        }

        public string GetLegacyIdentifier()
        {
            return E164number;
        }

        public bool Matches(SignalServiceAddress other)
        {
            return E164number == other.E164number;
        }

        public override bool Equals(object other)
        {
            if (other == null || !(other is SignalServiceAddress)) return false;

            SignalServiceAddress that = (SignalServiceAddress)other;

            return E164number == that.E164number && Relay == that.Relay;
        }

        public override int GetHashCode()
        {
            int hashCode = 0;

            if (E164number != null) hashCode ^= E164number.GetHashCode();
            if (Relay != null) hashCode ^= Relay.GetHashCode();

            return hashCode;
        }
    }
}
