namespace libsignalservice.messages
{
    public class SignalServiceTypingMessage
    {
        public enum Action
        {
            UNKNOWN, STARTED, STOPPED
        }

        public Action _Action { get; }
        public long Timestamp { get; }
        public byte[]? GroupId { get; }
        
        public SignalServiceTypingMessage(Action action, long timestamp, byte[]? groupId)
        {
            _Action = action;
            Timestamp = timestamp;
            GroupId = groupId;
        }

        public bool IsTypingStarted()
        {
            return _Action == Action.STARTED;
        }

        public bool IsTypingStopped()
        {
            return _Action == Action.STOPPED;
        }
    }
}
