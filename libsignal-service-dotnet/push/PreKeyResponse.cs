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
using System.Collections.Generic;
using libsignal;
using libsignalservice.util;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace libsignalservice.push
{
    class PreKeyResponse
    {

        [JsonProperty(Order = 1)]
        private List<PreKeyResponseItem> devices;

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(IdentityKeySerializer))]
        private IdentityKey identityKey;

        public PreKeyResponse()
        {

        }

        public IdentityKey getIdentityKey()
        {
            return identityKey;
        }

        public List<PreKeyResponseItem> getDevices()
        {
            return devices;
        }


    }

    class IdentityKeySerializer : JsonConverter
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
                    byte[] test = Base64.decodeWithoutPadding(str);
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
            writer.WriteValue(Base64.encodeBytesWithoutPadding(pubKey.serialize()));
        }
    }
}
