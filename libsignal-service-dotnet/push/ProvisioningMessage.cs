using Newtonsoft.Json;
using System;

namespace libsignalservice.push
{
    internal class ProvisioningMessage
    {
        [JsonProperty("body")]
        private String Body;

        public ProvisioningMessage(String body)
        {
            Body = body;
        }
    }
}
