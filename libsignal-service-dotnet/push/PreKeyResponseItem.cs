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
    class PreKeyResponseItem
    {

        [JsonProperty]
        private uint deviceId;

        [JsonProperty]
        private uint registrationId;

        [JsonProperty]
        private SignedPreKeyEntity signedPreKey;

        [JsonProperty]
        private PreKeyEntity preKey;

        public PreKeyResponseItem()
        {

        }

        public uint getDeviceId()
        {
            return deviceId;
        }

        public uint getRegistrationId()
        {
            return registrationId;
        }

        public SignedPreKeyEntity getSignedPreKey()
        {
            return signedPreKey;
        }

        public PreKeyEntity getPreKey()
        {
            return preKey;
        }

    }
}
