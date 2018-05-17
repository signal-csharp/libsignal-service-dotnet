using libsignal.ecc;
using libsignalservice.util;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using System;

namespace libsignalservice.push
{
    [JsonObject(MemberSerialization.OptIn)]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class PreKeyEntity
    {
        [JsonProperty("keyId")]
        public uint KeyId { get; set; }

        [JsonProperty("publicKey")]
        [JsonConverter(typeof(ECPublicKeySerializer))]
        public ECPublicKey PublicKey { get; set; }

        internal PreKeyEntity() { }

        internal PreKeyEntity(uint keyId, ECPublicKey publicKey)
        {
            KeyId = keyId;
            PublicKey = publicKey;
        }

        private class ECPublicKeySerializer : JsonConverter
        {
            public override bool CanConvert(Type objectType)
            {
                throw new NotImplementedException();
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                try
                {
                    var token = JToken.Load(reader);

                    string key = token.Value<string>();
                    return Curve.decodePoint(Base64.DecodeWithoutPadding(key), 0);
                }
                catch (Exception e)
                {
                    throw new Exception(e.Message);
                }
            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                ECPublicKey pubKey = (ECPublicKey)value;

                writer.WriteValue(Base64.EncodeBytesWithoutPadding(pubKey.serialize()));
            }
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
