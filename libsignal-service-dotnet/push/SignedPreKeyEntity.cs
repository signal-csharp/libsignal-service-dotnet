/** 
 * Copyright (C) 2017 smndtrl, golf1052
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using libsignal.ecc;
using libsignalservice.util;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace libsignalservice.push
{
    [JsonObject(MemberSerialization.OptIn)]
    [JsonConverter(typeof(SignedPreKeySerializer))]
    public class SignedPreKeyEntity : PreKeyEntity
    {

        private byte[] signature;

        public SignedPreKeyEntity() { }

        public SignedPreKeyEntity(uint keyId, ECPublicKey publicKey, byte[] signature)
            : base(keyId, publicKey)
        {
            this.signature = signature;
        }

        public byte[] getSignature()
        {
            return signature;
        }

        class SignedPreKeySerializer : JsonConverter
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
                    var publicKey = Curve.decodePoint(Base64.decodeWithoutPadding((string)token.SelectToken("publicKey")), 0);
                    var signature = Base64.decodeWithoutPadding((string)token.SelectToken("signature"));

                    return new SignedPreKeyEntity(keyId, publicKey, signature);
                }
                catch (Exception e)
                {
                    throw new Exception(e.Message);
                }

            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                //throw new NotImplementedException();
                //byte[] signature = (byte[])value;
                var signedPreKey = (SignedPreKeyEntity)value;
                writer.WriteStartObject();
                writer.WritePropertyName("keyId");
                writer.WriteValue(signedPreKey.getKeyId());
                writer.WritePropertyName("publicKey");
                writer.WriteValue(Base64.encodeBytesWithoutPadding(signedPreKey.getPublicKey().serialize()));
                writer.WritePropertyName("signature");
                writer.WriteValue(Base64.encodeBytesWithoutPadding(signedPreKey.signature));
                writer.WriteEndObject();
            }
        }
        /*
        class ByteArraySerializer : JsonConverter
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

                    string sign = token.Value<string>();
                    return Base64.decodeWithoutPadding(sign);
                }
                catch (Exception e)
                {
                    throw new Exception(e.Message);
                }

            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                byte[] signature = (byte[])value;
                writer.WriteValue(Base64.encodeBytesWithoutPadding(signature));
            }
        }*/
    }
}

