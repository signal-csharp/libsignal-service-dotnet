using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.push
{
    internal class ProfileAvatarUploadAttributes
    {
        public string Url { get; set; }
        public string Key { get; set; }
        public string Credential { get; set; }
        public string Acl { get; set; }
        public string Algorithm { get; set; }
        public string Date { get; set; }
        public string Policy { get; set; }
        public string Signature { get; set; }
    }
}
