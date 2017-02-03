/** 
 * Copyright (C) 2017 golf1052
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

using libsignalservice.messages.multidevice;
using Strilanc.Value;

namespace libsignalservice.messages
{
    public class SignalServiceContent
    {
        private readonly May<SignalServiceDataMessage> message;
        private readonly May<SignalServiceSyncMessage> synchronizeMessage;

        public SignalServiceContent()
        {
            message = May.NoValue;
            synchronizeMessage = May.NoValue;
        }

        public SignalServiceContent(SignalServiceDataMessage message)
        {
            this.message = new May<SignalServiceDataMessage>(message);
            synchronizeMessage = May.NoValue;
        }

        public SignalServiceContent(SignalServiceSyncMessage synchronizeMessage)
        {
            message = May.NoValue;
            this.synchronizeMessage = new May<SignalServiceSyncMessage>(synchronizeMessage);
        }

        public May<SignalServiceDataMessage> getDataMessage()
        {
            return message;
        }

        public May<SignalServiceSyncMessage> getSyncMessage()
        {
            return synchronizeMessage;
        }
    }
}
