using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.push
{
    public class ProfileAvatarUploadAttributes
    {
        public string url { get; }
        public string key { get; }
        public string credential { get; }
        public string acl { get; }
        public string algorithm { get; }
        public string date { get; }
        public string policy { get; }
        public string signature { get; }
    }
}
