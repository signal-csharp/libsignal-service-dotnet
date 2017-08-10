using libsignalservice.messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace libsignal.messages.multidevice
{
    public class ContactsMessage
    {
        public SignalServiceAttachment Contacts { get; }
        public bool Complete { get; }
    }
}
