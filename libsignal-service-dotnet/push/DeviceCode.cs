using Newtonsoft.Json;
using System;

namespace libsignalservice.push
{
    internal class DeviceCode
    {
        [JsonProperty("verificationCode")]
        public String VerificationCode { get; set; }
    }
}
