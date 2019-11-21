using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservicedotnet.crypto
{
    public class UnidentifiedAccessPair
    {
        public UnidentifiedAccess? TargetUnidentifiedAccess { get; }
        public UnidentifiedAccess? SelfUnidentifiedAccess { get; }

        public UnidentifiedAccessPair(UnidentifiedAccess targetUnidentifiedAccess, UnidentifiedAccess selfUnidentifiedAccess)
        {
            TargetUnidentifiedAccess = targetUnidentifiedAccess;
            SelfUnidentifiedAccess   = selfUnidentifiedAccess;
        }
    }
}
