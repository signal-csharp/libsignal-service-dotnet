using System;
using System.Collections.Generic;
using System.Text;
using libsignalservice.util;
using Newtonsoft.Json;

namespace libsignalservicedotnet.push
{
    public class SenderCertificate
    {
        [JsonProperty("certificate")]
        public string UnidentifiedCertificate { get; set; }

        public byte[] GetUnidentifiedCertificate()
        {
            return Base64.Decode(UnidentifiedCertificate);
        }

        public SenderCertificate(byte[] unidentifiedCertificate)
        {
            UnidentifiedCertificate = Base64.EncodeBytes(unidentifiedCertificate);
        }
    }
}
