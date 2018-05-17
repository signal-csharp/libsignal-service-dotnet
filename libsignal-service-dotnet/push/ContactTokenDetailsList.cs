using Newtonsoft.Json;
using System.Collections.Generic;

namespace libsignalservice.push
{
    [JsonObject(MemberSerialization.OptIn)]
    internal class ContactTokenDetailsList
    {
        [JsonProperty("contacts")]
        public List<ContactTokenDetails> Contacts { get; private set; }

        public ContactTokenDetailsList() { }
    }
}
