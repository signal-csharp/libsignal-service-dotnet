/** 
 * Copyright (C) 2015 smndtrl
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

using libsignalservice.crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libsignalservice.push.exceptions
{
    class EncapsulatedExceptions : Exception
    {

        private readonly IList<UntrustedIdentityException> untrustedIdentityExceptions;
        private readonly IList<UnregisteredUserException>  unregisteredUserExceptions;
        private readonly IList<NetworkFailureException>    networkExceptions;

        public EncapsulatedExceptions(IList<UntrustedIdentityException> untrustedIdentities,
                                      IList<UnregisteredUserException> unregisteredUsers,
                                      IList<NetworkFailureException> networkExceptions)
        {
            this.untrustedIdentityExceptions = untrustedIdentities;
            this.unregisteredUserExceptions = unregisteredUsers;
            this.networkExceptions = networkExceptions;
        }

        public EncapsulatedExceptions(UntrustedIdentityException e)
        {
            this.untrustedIdentityExceptions = new List<UntrustedIdentityException>();
            this.unregisteredUserExceptions = new List<UnregisteredUserException>();
            this.networkExceptions = new List<NetworkFailureException>();

            this.untrustedIdentityExceptions.Add(e);
        }

        public IList<UntrustedIdentityException> getUntrustedIdentityExceptions()
        {
            return untrustedIdentityExceptions;
        }

        public IList<UnregisteredUserException> getUnregisteredUserExceptions()
        {
            return unregisteredUserExceptions;
        }

        public IList<NetworkFailureException> getNetworkExceptions()
        {
            return networkExceptions;
        }
    }
}
