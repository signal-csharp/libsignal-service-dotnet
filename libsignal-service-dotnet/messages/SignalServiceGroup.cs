using Strilanc.Value;

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

using System;
using System.Collections.Generic;

namespace libsignalservice.messages
{
    /// <summary>
    /// Group information to include in SignalServiceMessages destined to groups.
    ///
    /// This class represents a "context" that is included with Signal Service messages
    /// to make them group messages.  There are three types of context:
    ///
    /// 1) Update -- Sent when either creating a group, or updating the properties
    /// of a group (such as the avatar icon, membership list, or title).
    /// 2) Deliver -- Sent when a message is to be delivered to an existing group.
    /// 3) Quit -- Sent when the sender wishes to leave an existing group.
    /// </summary>
    public class SignalServiceGroup
    {
        public enum GroupType
        {
            UNKNOWN,
            UPDATE,
            DELIVER,
            QUIT,
            REQUEST_INFO
        }

        public byte[] GroupId { get; set; }
        public GroupType Type { get; set; }
        public String Name { get; set; }
        public IList<String> Members { get; set; }
        public SignalServiceAttachment Avatar { get; set; }
    }
}
