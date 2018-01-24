/**
 * Copyright (C) 2018 golf1052, trolldemorted
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

using libsignal;

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

        public string Destination { get; private set; }

        public IdentityKey IdentityKey { get; private set; }

        public VerifiedState Verified { get; private set; }

        public VerifiedMessage(string destination, IdentityKey identityKey, VerifiedState verified)
        {
            Destination = destination;
            IdentityKey = identityKey;
            Verified = verified;
        }
    }
}
