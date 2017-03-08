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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Google.Protobuf;
using libsignal.util;
using libsignalservice.push;
using libsignalservice.util;
using System.Net.WebSockets;
using System.Runtime.CompilerServices;

namespace libsignalservice.websocket
{
    public class SignalWebSocketConnection
    {
        private static readonly string TAG = "WebSocketConnection";
        private static readonly int KEEPALIVE_TIMEOUT_SECONDS = 55;
        private static readonly Object obj = new Object();

        private readonly LinkedList<WebSocketRequestMessage> incomingRequests = new LinkedList<WebSocketRequestMessage>();

        private readonly string wsUri;
        private readonly TrustStore trustStore;
        private readonly CredentialsProvider credentialsProvider;
        private readonly string userAgent;
        WebsocketConnection Connection;
        public CancellationTokenSource tokenSource = new CancellationTokenSource();

        public SignalWebSocketConnection(string httpUri, TrustStore trustStore, CredentialsProvider credentialsProvider, string userAgent)
        {
            this.trustStore = trustStore;
            this.credentialsProvider = credentialsProvider;
            this.userAgent = userAgent;
            this.wsUri = httpUri.Replace("https://", "wss://")
                .Replace("http://", "ws://") + $"/v1/websocket/?login={credentialsProvider.GetUser()}&password={credentialsProvider.GetPassword()}";
            this.userAgent = userAgent;
        }

        public void Connect()
        {
            Debug.WriteLine("WebSocketConnection: connect()...");
            if (Connection == null)
            {
                Connection = new WebsocketConnection();
                Connection.OnMessage += Connection_OnMessage;
                Connection.OnOpened += Connection_OnOpened;
            }
            Connection.Open(wsUri);
        }

        private void Connection_OnOpened()
        {
            Debug.WriteLine("WebSocketConnection: opened!");
        }

        private void Connection_OnMessage(byte[] obj)
        {
            lock(obj)
            {
                var msg = WebSocketMessage.Parser.ParseFrom(obj);
                if(msg.Type == WebSocketMessage.Types.Type.Request)
                {
                    incomingRequests.AddLast(msg.Request);
                } else if(msg.Type == WebSocketMessage.Types.Type.Response)
                {
                    Debug.WriteLine("received response id=" + msg.Response.Id);
                }
            }
        }

        public void Disconnect()
        {
            Debug.WriteLine("WebSocketConnection disconnect()...");
            if (Connection != null)
            {
                Connection.Close();
                Connection = null;
            }
        }

        public WebSocketRequestMessage readRequest()
        {
            lock(obj)
            {
                if(incomingRequests.Count > 0)
                {
                    var m = incomingRequests.First.Value;
                    incomingRequests.RemoveFirst();
                    return m;
                }
            }
            return null;
        }

        public void SendRequest(WebSocketRequestMessage request)
        {
            if (Connection == null || !Connection.IsOpen)
            {
                throw new IOException("No connection!");
            }
            WebSocketMessage message = new WebSocketMessage
            {
                Type = WebSocketMessage.Types.Type.Request,
                Request = request
            };
            Connection.Send(message.ToByteArray());
        }

        public void sendResponse(WebSocketResponseMessage response)
        {
            if (Connection == null || !Connection.IsOpen)
            {
                throw new Exception("Connection closed!");
            }
            WebSocketMessage message = new WebSocketMessage
            {
                Type = WebSocketMessage.Types.Type.Response,
                Response = response
            };
            Connection.Send(message.ToByteArray());
        }

        private void sendKeepAlive(object state)
        {
            if (Connection != null && Connection.IsOpen)
            {
                Debug.WriteLine("keepAlive");
                WebSocketMessage message = new WebSocketMessage
                {
                    Type = WebSocketMessage.Types.Type.Request,
                    Request = new WebSocketRequestMessage
                    {
                        Id = KeyHelper.getTime(),
                        Path = "/v1/keepalive",
                        Verb = "GET"
                    },
                };
                Connection.Send(message.ToByteArray());
            }
        }
    }
}
