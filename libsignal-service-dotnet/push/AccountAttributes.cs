/** 
 * Copyright (C) 2015 smndtrl
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

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libsignalservice.push
{
    [JsonObject(MemberSerialization.OptIn)]
    class AccountAttributes
    {
        [JsonProperty("signalingKey", Required = Required.Always)]
        private String SignalingKey { get; set; }

        [JsonProperty("fetchesMessages", Required = Required.AllowNull)]
        private bool? FetchesMessages { get; set; } = null;

        [JsonProperty("registrationId", Required = Required.Always)]
        private uint RegistrationId { get; set; }

        [JsonProperty("name", Required = Required.AllowNull)]
        private string Name { get; set; }

        [JsonProperty("voice", Required = Required.AllowNull)]
        private bool? Voice { get; set; }

        public AccountAttributes() { }

        public AccountAttributes(string signalingKey, uint registrationId, bool? voice) {
            SignalingKey = signalingKey;
            RegistrationId = registrationId;
            Voice = voice;          
        }

        public AccountAttributes(string signalingKey, uint registrationId, bool? voice, string name, bool? fetchesMessages)
        {
            SignalingKey = signalingKey;
            RegistrationId = registrationId;
            Voice = voice;
            Name = name;
            FetchesMessages = fetchesMessages;
        }

    }
}
