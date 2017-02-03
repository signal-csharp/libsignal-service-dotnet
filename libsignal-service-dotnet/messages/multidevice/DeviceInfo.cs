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

namespace libsignalservice.messages.multidevice
{
    public class DeviceInfo
    {

        [JsonProperty]
        private long id;

        [JsonProperty]
        private String name;

        [JsonProperty]
        private long created;

        [JsonProperty]
        private long lastSeen;

        public DeviceInfo() { }

        public long getId()
        {
            return id;
        }

        public String getName()
        {
            return name;
        }

        public long getCreated()
        {
            return created;
        }

        public long getLastSeen()
        {
            return lastSeen;
        }
    }
}
