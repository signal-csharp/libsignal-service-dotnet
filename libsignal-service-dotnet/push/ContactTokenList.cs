using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace libsignalservice.push
{
    [JsonObject(MemberSerialization.OptIn)]
    internal class ContactTokenList
    {
        [JsonProperty("contacts")]
        public List<String> Contacts { get; }

        public ContactTokenList(List<String> contacts)
        {
            Contacts = contacts;
        }
    }
}
