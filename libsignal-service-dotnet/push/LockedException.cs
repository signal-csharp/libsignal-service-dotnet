using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class LockedException : Exception
    {
        public int Length { get; }
        public long TimeRemaining { get; }

        public LockedException(int length, long timeRemaining)
        {
            Length = length;
            TimeRemaining = timeRemaining;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
