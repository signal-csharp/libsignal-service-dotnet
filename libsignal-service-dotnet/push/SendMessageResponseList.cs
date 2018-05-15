using libsignalservice.crypto;
using libsignalservice.push.exceptions;
using System.Collections.Generic;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SendMessageResponseList
    {
        public List<UntrustedIdentityException> UntrustedIdentities = new List<UntrustedIdentityException>();
        public List<UnregisteredUserException> UnregisteredUsers = new List<UnregisteredUserException>();
        public List<NetworkFailureException> NetworkExceptions = new List<NetworkFailureException>();
        public bool NeedsSync;

        public bool HasExceptions()
        {
            return UntrustedIdentities.Count != 0 || UnregisteredUsers.Count != 0 || NetworkExceptions.Count != 0;
        }

        public void AddResponse(SendMessageResponse response)
        {
            if(!NeedsSync && response.NeedsSync)
            {
                NeedsSync = true;
            }
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
