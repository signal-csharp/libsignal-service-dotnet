using Newtonsoft.Json;
using System.Collections.Generic;

namespace libsignalservice.push
{
    internal class SignalServiceEnvelopeEntityList
    {
        [JsonProperty("messages")]
        public List<SignalServiceEnvelopeEntity> Messages { get; private set; }

        public SignalServiceEnvelopeEntityList() { }
    }
}
