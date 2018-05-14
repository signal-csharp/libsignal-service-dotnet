using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.websocket
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public interface ConnectivityListener
    {
        void OnConnected();
        void OnConnecting();
        void OnDisconnected();
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
