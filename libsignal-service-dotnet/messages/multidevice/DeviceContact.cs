/** 
 * Copyright (C) 2015-2017 smndtrl, golf1052
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

namespace libsignalservice.messages.multidevice
{
    public class DeviceContact
    {
        private readonly string number;
        private readonly May<string> name;
        private readonly May<SignalServiceAttachmentStream> avatar;
        private readonly May<string> color;

        public DeviceContact(string number,
            May<string> name,
            May<SignalServiceAttachmentStream> avatar,
            May<string> color)
        {
            this.number = number;
            this.name = name;
            this.avatar = avatar;
            this.color = color;
        }

        public May<SignalServiceAttachmentStream> getAvatar()
        {
            return avatar;
        }

        public May<string> getName()
        {
            return name;
        }

        public string getNumber()
        {
            return number;
        }

        public May<string> getColor()
        {
            return color;
        }
    }
}
