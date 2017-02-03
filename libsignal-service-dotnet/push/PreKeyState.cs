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

using System.Collections.Generic;
using libsignal;
using Newtonsoft.Json;

namespace libsignalservice.push
{
    [JsonObject(MemberSerialization.OptIn)]
    public class PreKeyState
    {

        [JsonProperty(Required = Required.Always, Order = 1)]
        [JsonConverter(typeof(IdentityKeySerializer))]
        private IdentityKey identityKey;

        [JsonProperty( Required = Required.Always, Order = 2)]
        private List<PreKeyEntity> preKeys;

        [JsonProperty( Required = Required.Always, Order = 3)]
        private PreKeyEntity lastResortKey;

        [JsonProperty( Required = Required.Always, Order = 4)]
        private SignedPreKeyEntity signedPreKey;


        public PreKeyState(List<PreKeyEntity> preKeys, PreKeyEntity lastResortKey,
                           SignedPreKeyEntity signedPreKey, IdentityKey identityKey)
        {
            this.preKeys = preKeys;
            this.lastResortKey = lastResortKey;
            this.signedPreKey = signedPreKey;
            this.identityKey = identityKey;
        }

    }
}
