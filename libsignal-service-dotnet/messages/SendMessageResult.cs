using System;
using System.Collections.Generic;
using System.Text;
using libsignal;
using libsignalservice.push;

namespace libsignalservicedotnet.messages
{
    public class SendMessageResult
    {

        public SignalServiceAddress Address;
        public SendMessageResultSuccess? Success;
        public bool NetworkFailure;
        public bool UnregisteredFailure;
        public SendMessageResultIdentityFailure? IdentityFailure;

        private SendMessageResult(SignalServiceAddress address, SendMessageResultSuccess? success, bool networkFailure, bool unregisteredFailure, SendMessageResultIdentityFailure? identityFailure)
        {
            Address             = address;
            Success             = success;
            NetworkFailure      = networkFailure;
            UnregisteredFailure = unregisteredFailure;
            IdentityFailure     = identityFailure;
        }

        public static SendMessageResult NewSuccess(SignalServiceAddress address, bool unidentified, bool needsSync)
        {
            return new SendMessageResult(address, new SendMessageResultSuccess(unidentified, needsSync), false, false, null);
        }

        public static SendMessageResult NewNetworkFailure(SignalServiceAddress address)
        {
            return new SendMessageResult(address, null, true, false, null);
        }

        public static SendMessageResult NewUnregisteredFailure(SignalServiceAddress address)
        {
            return new SendMessageResult(address, null, false, true, null);
        }

        public static SendMessageResult NewIdentityFailure(SignalServiceAddress address, IdentityKey identityKey)
        {
            return new SendMessageResult(address, null, false, false, new SendMessageResultIdentityFailure(identityKey));
        }


        public class SendMessageResultSuccess
        {
            public bool Unidentified { get; }
            public bool NeedsSync { get; }

            internal SendMessageResultSuccess(bool unidentified, bool needsSync)
            {
                Unidentified = unidentified;
                NeedsSync    = needsSync;
            }
        }

        public class SendMessageResultIdentityFailure
        {
            public IdentityKey IdentityKey { get; }

            internal SendMessageResultIdentityFailure(IdentityKey identityKey)
            {
                IdentityKey = identityKey;
            }
        }
    }
}
