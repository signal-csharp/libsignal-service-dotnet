using libsignal.ecc;
using libsignalservice.util;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using System;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    [JsonObject(MemberSerialization.OptIn)]
    [JsonConverter(typeof(SignedPreKeySerializer))]
    public class SignedPreKeyEntity : PreKeyEntity
    {
        public byte[] Signature { get; private set; }

        public SignedPreKeyEntity(uint keyId, ECPublicKey publicKey, byte[] signature)
            : base(keyId, publicKey)
        {
            this.Signature = signature;
        }

        private class SignedPreKeySerializer : JsonConverter
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
                    var keyId = (uint)token.SelectToken("keyId");
                    var publicKey = Curve.decodePoint(Base64.DecodeWithoutPadding((string)token.SelectToken("publicKey")), 0);
                    var signature = Base64.DecodeWithoutPadding((string)token.SelectToken("signature"));

                    return new SignedPreKeyEntity(keyId, publicKey, signature);
                }
                catch (Exception e)
                {
                    throw new Exception(e.Message);
                }
            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                var signedPreKey = (SignedPreKeyEntity)value;
                writer.WriteStartObject();
                writer.WritePropertyName("keyId");
                writer.WriteValue(signedPreKey.KeyId);
                writer.WritePropertyName("publicKey");
                writer.WriteValue(Base64.EncodeBytesWithoutPadding(signedPreKey.PublicKey.serialize()));
                writer.WritePropertyName("signature");
                writer.WriteValue(Base64.EncodeBytesWithoutPadding(signedPreKey.Signature));
                writer.WriteEndObject();
            }
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
