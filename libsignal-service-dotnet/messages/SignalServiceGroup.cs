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
using Strilanc.Value;

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
        public enum Type
        {
            UNKNOWN,
            UPDATE,
            DELIVER,
            QUIT,
            REQUEST_INFO
        }

        private readonly byte[] groupId;
        private readonly Type type;
        private readonly May<String> name;
        private readonly May<IList<String>> members;
        private readonly May<SignalServiceAttachment> avatar;

        /// <summary>
        /// Construct a DELIVER group context.
        /// </summary>
        /// <param name="groupId"></param>
        public SignalServiceGroup(byte[] groupId)
                 : this(Type.DELIVER, groupId, null, null, null)
        {
        }

        /// <summary>
        /// Construct a group context.
        /// </summary>
        /// <param name="type">The group message type (update, deliver, quit).</param>
        /// <param name="groupId">The group ID.</param>
        /// <param name="name">The group title.</param>
        /// <param name="members">The group membership list.</param>
        /// <param name="avatar">The group avatar icon.</param>
        public SignalServiceGroup(Type type, byte[] groupId, String name,
                               IList<String> members,
                               SignalServiceAttachment avatar)
        {
            this.type = type;
            this.groupId = groupId;
            this.name = new May<String>(name);
            this.members = new May<IList<String>>(members);
            this.avatar = new May<SignalServiceAttachment>(avatar);
        }

        public byte[] getGroupId()
        {
            return groupId;
        }

        public Type getType()
        {
            return type;
        }

        public May<String> getName()
        {
            return name;
        }

        public May<IList<String>> getMembers()
        {
            return members;
        }

        public May<SignalServiceAttachment> getAvatar()
        {
            return avatar;
        }

        public  Builder newUpdateBuilder()
        {
            return new Builder(Type.UPDATE);
        }

        public  Builder newBuilder(Type type)
        {
            return new Builder(type);
        }

        public class Builder
        {

            private Type type;
            private byte[] id;
            private String name;
            private List<String> members;
            private SignalServiceAttachment avatar;

            internal Builder(Type type)
            {
                this.type = type;
            }

            public Builder withId(byte[] id)
            {
                this.id = id;
                return this;
            }

            public Builder withName(String name)
            {
                this.name = name;
                return this;
            }

            public Builder withMembers(List<String> members)
            {
                this.members = members;
                return this;
            }

            public Builder withAvatar(SignalServiceAttachment avatar)
            {
                this.avatar = avatar;
                return this;
            }

            public SignalServiceGroup build()
            {
                if (id == null) throw new Exception("No group ID specified!");

                if (type == Type.UPDATE && name == null && members == null && avatar == null)
                {
                    throw new Exception("Group update with no updates!");
                }

                return new SignalServiceGroup(type, id, name, members, avatar);
            }

        }
    }
        
}
