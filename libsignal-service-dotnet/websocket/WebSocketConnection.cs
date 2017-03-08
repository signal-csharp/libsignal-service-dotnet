using System;
using System.Collections.Generic;

namespace libsignalservice.websocket
{
    /// <summary>
    /// A Websocket connection for 'full' .Net Core applications
    /// </summary>
    public class WebsocketConnection
    {
        public bool IsOpen { get; private set; }

        public event Action OnClosed = delegate { };
        public event Action OnOpened = delegate { };
        public event Action OnDispose = delegate { };
        public event Action<string> OnError = delegate { };
        public event Action<byte[]> OnMessage = delegate { };
        public event Action<string> OnLog = delegate { };

        static WebsocketConnection()
        {
        }

        private WebSocketWrapper _websocket = null;

        public void Open(string url, string protocol = null, string authToken = null)
        {
            var headers = new Dictionary<string, string>();
            if (authToken != null)
            {
                headers.Add("Authorization", authToken);
            }
            Open(url, protocol, headers);
        }

        public async void Open(string url, string protocol, IDictionary<string, string> headers = null)
        {
            try
            {
                if (_websocket != null)
                    EndConnection();

                _websocket = new WebSocketWrapper();
                _websocket.Closed += _websocket_Closed;
                _websocket.Opened += _websocket_Opened;
                _websocket.Error += _websocket_Error;
                _websocket.MessageReceived += _websocket_MessageReceived;

                if (url.StartsWith("https"))
                    url = url.Replace("https://", "wss://");
                else if (url.StartsWith("http"))
                    url = url.Replace("http://", "ws://");

                await _websocket.Connect(url, protocol, headers);

            }
            catch (Exception ex)
            {
                OnError(ex.Message);
            }
        }

        public void Close()
        {
            EndConnection();
        }

        public async void Send(byte[] message)
        {
            await _websocket.SendMessage(message);
        }


        public void Dispose()
        {
            Close();
            OnDispose();
        }

        //
        void EndConnection()
        {
            if (_websocket != null)
            {
                _websocket.Closed -= _websocket_Closed;
                _websocket.Opened -= _websocket_Opened;
                _websocket.Error -= _websocket_Error;
                _websocket.MessageReceived -= _websocket_MessageReceived;
                _websocket.Dispose();
                _websocket = null;
                IsOpen = false;
                OnClosed();
            }
        }


        void _websocket_Error(Exception obj)
        {
            OnError(obj.Message);
        }

        void _websocket_Opened(WebSocketWrapper arg)
        {
            IsOpen = true;
            OnOpened();
        }

        void _websocket_MessageReceived(byte[] m, WebSocketWrapper arg)
        {
            OnMessage(m);
        }

        void _websocket_Closed(WebSocketWrapper arg)
        {
            EndConnection();
        }
    }
}