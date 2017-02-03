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

using System.Collections.Generic;
using Strilanc.Value;

namespace libsignalservice.messages.multidevice
{
    public class SignalServiceSyncMessage
    {
        private readonly May<SentTranscriptMessage> sent;
        private readonly May<SignalServiceAttachment> contacts;
        private readonly May<SignalServiceAttachment> groups;
        private readonly May<BlockedListMessage> blockedList;
        private readonly May<RequestMessage> request;
        private readonly May<List<ReadMessage>> reads;

        private SignalServiceSyncMessage(May<SentTranscriptMessage> sent,
            May<SignalServiceAttachment> contacts,
            May<SignalServiceAttachment> groups,
            May<BlockedListMessage> blockedList,
            May<RequestMessage> request,
            May<List<ReadMessage>> reads)
        {
            this.sent = sent;
            this.contacts = contacts;
            this.groups = groups;
            this.blockedList = blockedList;
            this.request = request;
            this.reads = reads;
        }

        public static SignalServiceSyncMessage forSentTranscript(SentTranscriptMessage sent)
        {
            return new SignalServiceSyncMessage(new May<SentTranscriptMessage>(sent),
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue);
        }

        public static SignalServiceSyncMessage forContacts(SignalServiceAttachment contacts)
        {
            return new SignalServiceSyncMessage(May.NoValue,
                new May<SignalServiceAttachment>(contacts),
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue);
        }

        public static SignalServiceSyncMessage forGroups(SignalServiceAttachment groups)
        {
            return new SignalServiceSyncMessage(May.NoValue,
                May.NoValue,
                new May<SignalServiceAttachment>(groups),
                May.NoValue,
                May.NoValue,
                May.NoValue);
        }

        public static SignalServiceSyncMessage forRequest(RequestMessage request)
        {
            return new SignalServiceSyncMessage(May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                new May<RequestMessage>(request),
                May.NoValue);
        }

        public static SignalServiceSyncMessage forRead(List<ReadMessage> reads)
        {
            return new SignalServiceSyncMessage(May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                new May<List<ReadMessage>>(reads));
        }

        public static SignalServiceSyncMessage forRead(ReadMessage read)
        {
            List<ReadMessage> reads = new List<ReadMessage>();
            reads.Add(read);

            return new SignalServiceSyncMessage(May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                new May<List<ReadMessage>>(reads));
        }

        public static SignalServiceSyncMessage forBlocked(BlockedListMessage blocked)
        {
            return new SignalServiceSyncMessage(May.NoValue,
                May.NoValue,
                May.NoValue,
                new May<BlockedListMessage>(blocked),
                May.NoValue,
                May.NoValue);
        }

        public static SignalServiceSyncMessage empty()
        {
            return new SignalServiceSyncMessage(May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue);
        }

        public May<SentTranscriptMessage> getSent()
        {
            return sent;
        }

        public May<SignalServiceAttachment> getGroups()
        {
            return groups;
        }

        public May<SignalServiceAttachment> getContacts()
        {
            return contacts;
        }

        public May<RequestMessage> getRequest()
        {
            return request;
        }

        public May<List<ReadMessage>> getRead()
        {
            return reads;
        }

        public May<BlockedListMessage> getBlockedList()
        {
            return blockedList;
        }
    }
}
