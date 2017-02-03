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

using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libsignalservice.messages.multidevice
{
    public class DeviceGroup
    {

        private readonly byte[] id;
        private readonly May<String> name;
        private readonly IList<String> members;
        private readonly May<SignalServiceAttachmentStream> avatar;
        private readonly bool active;

        public DeviceGroup(byte[] id, May<String> name, IList<String> members, May<SignalServiceAttachmentStream> avatar, bool active)
        {
            this.id = id;
            this.name = name;
            this.members = members;
            this.avatar = avatar;
            this.active = active;
        }

        public May<SignalServiceAttachmentStream> getAvatar()
        {
            return avatar;
        }

        public May<String> getName()
        {
            return name;
        }

        public byte[] getId()
        {
            return id;
        }

        public IList<String> getMembers()
        {
            return members;
        }

        public bool isActive()
        {
            return active;
        }

    }
}
