using libsignal;

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

namespace libsignalservice.crypto
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class UntrustedIdentityException : Exception
    {
        public IdentityKey IdentityKey { get; }
        public String E164number { get; }

        public UntrustedIdentityException(String s, String e164number, IdentityKey identityKey)
                  : base(s)
        {
            E164number = e164number;
            IdentityKey = identityKey;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
