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
using Strilanc.Value;

namespace libsignalservice.push
{
    /// <summary>
    /// A class representing a message destination or origin.
    /// </summary>
    public class SignalServiceAddress
    {
        public static readonly uint DEFAULT_DEVICE_ID = 1;

        private readonly String e164number;
        private readonly May<String> relay;

        /// <summary>
        /// Construct a PushAddress.
        /// </summary>
        /// <param name="e164number">The Signal Service username of this destination (eg e164 representation of a phone number).</param>
        /// <param name="relay">The Signal Service federated server this user is registered with (if not your own server).</param>
        public SignalServiceAddress(String e164number, May<String> relay)
        {
            this.e164number = e164number;
            this.relay = relay;
        }

        public SignalServiceAddress(String e164number)
            : this(e164number, new May<String>())
        {
        }

        public String getNumber()
        {
            return e164number;
        }

        public May<String> getRelay()
        {
            return relay;
        }

        public override bool Equals(Object other)
        {
            if (other == null || !(other is SignalServiceAddress)) return false;

            SignalServiceAddress that = (SignalServiceAddress)other;

            return equals(this.e164number,that.e164number) &&
                   equals(this.relay,that.relay);
        }

        public override int GetHashCode()
        {
            int hashCode = 0;

            if (this.e164number != null) hashCode ^= this.e164number.GetHashCode();
            if (this.relay.HasValue) hashCode ^= this.relay.ForceGetValue().GetHashCode();

            return hashCode;
        }

        private bool equals(String one, String two)
        {
            if (one == null) return two == null;
            return one.Equals(two);
        }

        private bool equals(May<String> one, May<String> two)
        {
            if (one.HasValue) {
                return two.HasValue && one.ForceGetValue().Equals(two.ForceGetValue());
            }
            else return !two.HasValue;
        }
    }
}
