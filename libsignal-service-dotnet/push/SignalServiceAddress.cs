using Strilanc.Value;

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

using System;

namespace libsignalservice.push
{
    /// <summary>
    /// A class representing a message destination or origin.
    /// </summary>
    public class SignalServiceAddress
    {
        public static readonly uint DEFAULT_DEVICE_ID = 1;

        public string E164number { get; }
        public string Relay { get; }

        /// <summary>
        /// Construct a PushAddress.
        /// </summary>
        /// <param name="e164number">The Signal Service username of this destination (eg e164 representation of a phone number).</param>
        /// <param name="relay">The Signal Service federated server this user is registered with (if not your own server).</param>
        public SignalServiceAddress(string e164number, string relay)
        {
            E164number = e164number;
            Relay = relay;
        }

        public SignalServiceAddress(string e164number)
        {
            E164number = e164number;
        }

        public override bool Equals(Object other)
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
