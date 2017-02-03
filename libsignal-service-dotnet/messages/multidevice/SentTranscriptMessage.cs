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
    public class SentTranscriptMessage
    {
        private readonly May<string> destination;
        private readonly long timestamp;
        private readonly long expirationStartTimestamp;
        private readonly SignalServiceDataMessage message;

        public SentTranscriptMessage(string destination, long timestamp, SignalServiceDataMessage message, long expirationStartTimestamp)
        {
            this.destination = new May<string>(destination);
            this.timestamp = timestamp;
            this.message = message;
            this.expirationStartTimestamp = expirationStartTimestamp;
        }

        public SentTranscriptMessage(long timestamp, SignalServiceDataMessage message)
        {
            this.destination = May.NoValue;
            this.timestamp = timestamp;
            this.message = message;
            this.expirationStartTimestamp = 0;
        }

        public May<string> getDestination()
        {
            return destination;
        }

        public long getTimestamp()
        {
            return timestamp;
        }

        public long getExpirationStartTimestamp()
        {
            return expirationStartTimestamp;
        }

        public SignalServiceDataMessage getMessage()
        {
            return message;
        }
    }
}