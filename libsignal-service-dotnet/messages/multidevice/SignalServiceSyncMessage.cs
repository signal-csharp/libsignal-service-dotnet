using System.Collections.Generic;
using libsignal.messages.multidevice;

namespace libsignalservice.messages.multidevice
{
    public class SignalServiceSyncMessage
    {
        public SentTranscriptMessage? Sent { get; }
        public ContactsMessage? Contacts { get; }
        public SignalServiceAttachment? Groups { get; }
        public BlockedListMessage? BlockedList { get; }
        public RequestMessage? Request { get; }
        public List<ReadMessage>? Reads { get; }
        public ViewOnceOpenMessage? ViewOnceOpen { get; }
        public VerifiedMessage? Verified { get; }
        public ConfigurationMessage? Configuration { get; }
        public List<StickerPackOperationMessage>? StickerPackOperations { get; }

        private SignalServiceSyncMessage(SentTranscriptMessage? sent,
            ContactsMessage? contacts,
            SignalServiceAttachment? groups,
            BlockedListMessage? blockedList,
            RequestMessage? request,
            List<ReadMessage>? reads,
            ViewOnceOpenMessage? viewOnceOpen,
            VerifiedMessage? verified,
            ConfigurationMessage? configuration,
            List<StickerPackOperationMessage>? stickerPackOperations)
        {
            Sent = sent;
            Contacts = contacts;
            Groups = groups;
            BlockedList = blockedList;
            Request = request;
            Reads = reads;
            ViewOnceOpen = viewOnceOpen;
            Verified = verified;
            Configuration = configuration;
            StickerPackOperations = stickerPackOperations;
        }

        public static SignalServiceSyncMessage ForSentTranscript(SentTranscriptMessage sent)
        {
            return new SignalServiceSyncMessage(sent,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null);
        }

        public static SignalServiceSyncMessage ForContacts(ContactsMessage contacts)
        {
            return new SignalServiceSyncMessage(null,
                contacts,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null);
        }

        public static SignalServiceSyncMessage ForGroups(SignalServiceAttachment groups)
        {
            return new SignalServiceSyncMessage(null,
                null,
                groups,
                null,
                null,
                null,
                null,
                null,
                null,
                null);
        }

        public static SignalServiceSyncMessage ForRequest(RequestMessage request)
        {
            return new SignalServiceSyncMessage(null,
                null,
                null,
                null,
                request,
                null,
                null,
                null,
                null,
                null);
        }

        public static SignalServiceSyncMessage ForRead(List<ReadMessage> reads)
        {
            return new SignalServiceSyncMessage(null,
                null,
                null,
                null,
                null,
                reads,
                null,
                null,
                null,
                null);
        }

        public static SignalServiceSyncMessage ForRead(ReadMessage read)
        {
            List<ReadMessage> reads = new List<ReadMessage> { read };

            return new SignalServiceSyncMessage(null,
                null,
                null,
                null,
                null,
                reads,
                null,
                null,
                null,
                null);
        }

        public static SignalServiceSyncMessage ForViewOnceOpen(ViewOnceOpenMessage timerRead)
        {
            return new SignalServiceSyncMessage(null,
                null,
                null,
                null,
                null,
                null,
                timerRead,
                null,
                null,
                null);
        }

        public static SignalServiceSyncMessage ForVerified(VerifiedMessage verifiedMessage)
        {
            return new SignalServiceSyncMessage(null,
                null,
                null,
                null,
                null,
                null,
                null,
                verifiedMessage,
                null,
                null);
        }

        public static SignalServiceSyncMessage ForBlocked(BlockedListMessage blocked)
        {
            return new SignalServiceSyncMessage(null,
                null,
                null,
                blocked,
                null,
                null,
                null,
                null,
                null,
                null);
        }

        public static SignalServiceSyncMessage ForConfiguration(ConfigurationMessage configuration)
        {
            return new SignalServiceSyncMessage(null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                configuration,
                null);
        }

        public static SignalServiceSyncMessage ForStickerPackOperations(List<StickerPackOperationMessage> stickerPackOperations)
        {
            return new SignalServiceSyncMessage(null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                stickerPackOperations);
        }

        public static SignalServiceSyncMessage Empty()
        {
            return new SignalServiceSyncMessage(null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null);
        }
    }
}
