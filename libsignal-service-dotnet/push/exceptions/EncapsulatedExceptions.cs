using libsignalservice.crypto;
using System;
using System.Collections.Generic;

namespace libsignalservice.push.exceptions
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class EncapsulatedExceptions : Exception
    {
        public IList<UntrustedIdentityException> UntrustedIdentityExceptions;
        public IList<UnregisteredUserException> UnregisteredUserExceptions;
        public IList<NetworkFailureException> NetworkExceptions;

        public EncapsulatedExceptions(IList<UntrustedIdentityException> untrustedIdentities,
                                      IList<UnregisteredUserException> unregisteredUsers,
                                      IList<NetworkFailureException> networkExceptions)
        {
            UntrustedIdentityExceptions = untrustedIdentities;
            UnregisteredUserExceptions = unregisteredUsers;
            NetworkExceptions = networkExceptions;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
