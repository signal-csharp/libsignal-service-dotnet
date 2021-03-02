using System;
using libsignalservice.util;

namespace libsignalservice.push
{
    /// <summary>
    /// A class representing a message destination or origin.
    /// </summary>
    public class SignalServiceAddress
    {
        public static readonly uint DEFAULT_DEVICE_ID = 1;

        public Guid? Uuid { get; }
        public string? E164 { get; }
        public string? Relay { get; }

        /// <summary>
        /// Construct a PushAddress.
        /// </summary>
        /// <param name="uuid">The Guid of the user, if available.</param>
        /// <param name="e164">The phone number of the user, if available.</param>
        /// <param name="relay">The Signal service federated server this user is registered with (if not your own server).</param>
        public SignalServiceAddress(Guid? uuid, string? e164, string? relay)
        {
            Uuid = uuid;
            E164 = e164;
            Relay = relay;
        }

        /// <summary>
        /// Convenience constructor that will consider a UUID/E164 string absent if it is null or empty.
        /// </summary>
        /// <param name="uuid"></param>
        /// <param name="e164"></param>
        public SignalServiceAddress(Guid? uuid, string? e164) :
            this(uuid, !string.IsNullOrEmpty(e164) ? e164 : null, null)
        {
        }

        public string? GetNumber()
        {
            return E164;
        }

        public string? GetIdentifier()
        {
            if (Uuid.HasValue)
            {
                return Uuid.Value.ToString();
            }
            else if (E164 != null)
            {
                return E164;
            }
            else
            {
                return null;
            }
        }

        public string? GetLegacyIdentifier()
        {
            return E164;
        }

        public bool Matches(SignalServiceAddress other)
        {
            return (Uuid.HasValue && other.Uuid.HasValue && Uuid.Value == other.Uuid.Value) ||
                (E164 != null && other.E164 != null && E164 == other.E164);
        }

        public static bool IsValidAddress(string? rawUuid, string? e164)
        {
            return !string.IsNullOrEmpty(e164) || UuidUtil.ParseOrNull(rawUuid) != null;
        }

        public static SignalServiceAddress? FromRaw(string? rawUuid, string? e164)
        {
            if (IsValidAddress(rawUuid, e164))
            {
                return new SignalServiceAddress(UuidUtil.ParseOrNull(rawUuid), e164);
            }
            else
            {
                return null;
            }
        }

        public static bool operator ==(SignalServiceAddress? a, SignalServiceAddress? b)
        {
            if (object.ReferenceEquals(a, null))
            {
                return object.ReferenceEquals(b, null);
            }

            return a.Equals(b);
        }

        public static bool operator !=(SignalServiceAddress? a, SignalServiceAddress? b)
        {
            return !(a == b);
        }

        public override bool Equals(object? other)
        {
            if (other == null || !(other is SignalServiceAddress)) return false;

            SignalServiceAddress that = (SignalServiceAddress)other;

            return Uuid == that.Uuid &&
                E164 == that.E164 &&
                Relay == that.Relay;
        }

        public override int GetHashCode()
        {
            int hashCode = 0;

            if (Uuid.HasValue) hashCode ^= Uuid.Value.GetHashCode();
            if (E164 != null) hashCode ^= E164.GetHashCode();
            if (Relay != null) hashCode ^= Relay.GetHashCode();

            return hashCode;
        }
    }
}
