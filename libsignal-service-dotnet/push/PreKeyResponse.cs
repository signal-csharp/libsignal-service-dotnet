using libsignal;
using libsignalservice.util;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using System;
using System.Collections.Generic;

namespace libsignalservice.push
{
    internal class PreKeyResponse
    {
        [JsonProperty("devices", Order = 1)]
        public List<PreKeyResponseItem> Devices { get; private set; }

        [JsonProperty("identityKey", Order = 2)]
        [JsonConverter(typeof(IdentityKeySerializer))]
        public IdentityKey IdentityKey { get; private set; }

        public PreKeyResponse() { }
    }

    internal class IdentityKeySerializer : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            throw new NotImplementedException();
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            try
            {
                var token = JToken.Load(reader); // skip devices token

                var str = token.Value<string>();
                byte[] test = Base64.DecodeWithoutPadding(str);
                return new IdentityKey(test, 0);
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }

            throw new NotImplementedException();
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            IdentityKey pubKey = (IdentityKey)value;
            writer.WriteValue(Base64.EncodeBytesWithoutPadding(pubKey.serialize()));
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
