using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.push
{
    internal class ProfileAvatarUploadAttributes
    {
        public string Url { get; private set; }
        public string Key { get; private set; }
        public string Credential { get; private set; }
        public string Acl { get; private set; }
        public string Algorithm { get; private set; }
        public string Date { get; private set; }
        public string Policy { get; private set; }
        public string Signature { get; private set; }

        public ProfileAvatarUploadAttributes() { }
    }
}
