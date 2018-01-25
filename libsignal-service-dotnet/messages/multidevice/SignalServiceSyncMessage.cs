using libsignal.messages.multidevice;
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

using System.Collections.Generic;

namespace libsignalservice.messages.multidevice
{
    public class SignalServiceSyncMessage
    {
        private readonly May<SentTranscriptMessage> sent;
        private readonly May<ContactsMessage> contacts;
        private readonly May<SignalServiceAttachment> groups;
        private readonly May<BlockedListMessage> blockedList;
        private readonly May<RequestMessage> request;
        private readonly May<List<ReadMessage>> reads;
        private readonly May<VerifiedMessage> verified;

        private SignalServiceSyncMessage(May<SentTranscriptMessage> sent,
            May<ContactsMessage> contacts,
            May<SignalServiceAttachment> groups,
            May<BlockedListMessage> blockedList,
            May<RequestMessage> request,
            May<List<ReadMessage>> reads,
            May<VerifiedMessage> verified)
        {
            this.sent = sent;
            this.contacts = contacts;
            this.groups = groups;
            this.blockedList = blockedList;
            this.request = request;
            this.reads = reads;
            this.verified = verified;
        }

        public static SignalServiceSyncMessage forSentTranscript(SentTranscriptMessage sent)
        {
            return new SignalServiceSyncMessage(new May<SentTranscriptMessage>(sent),
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue);
        }

        public static SignalServiceSyncMessage forContacts(ContactsMessage contacts)
        {
            return new SignalServiceSyncMessage(May.NoValue,
                new May<ContactsMessage>(contacts),
                May.NoValue,
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
                May.NoValue,
                May.NoValue);
        }

        public static SignalServiceSyncMessage forRead(List<ReadMessage> reads)
        {
            return new SignalServiceSyncMessage(May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                new May<List<ReadMessage>>(reads),
                May.NoValue);
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
                new May<List<ReadMessage>>(reads),
                May.NoValue);
        }

        public static SignalServiceSyncMessage forVerified(VerifiedMessage verifiedMessage)
        {
            return new SignalServiceSyncMessage(May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                May.NoValue,
                new May<VerifiedMessage>(verifiedMessage));
        }

        public static SignalServiceSyncMessage forBlocked(BlockedListMessage blocked)
        {
            return new SignalServiceSyncMessage(May.NoValue,
                May.NoValue,
                May.NoValue,
                new May<BlockedListMessage>(blocked),
                May.NoValue,
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

        public May<ContactsMessage> getContacts()
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

        public May<VerifiedMessage> getVerified()
        {
            return verified;
        }
    }
}
