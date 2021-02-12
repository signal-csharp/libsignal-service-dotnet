using libsignalservice.push.exceptions;

namespace libsignalservice.push
{
    public class LockedException : NonSuccessfulResponseCodeException
    {
        public int Length { get; }
        public long TimeRemaining { get; }

        public LockedException(int length, long timeRemaining) : base(423)
        {
            Length = length;
            TimeRemaining = timeRemaining;
        }
    }
}
