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
using System.Collections.Concurrent;
using Coe.WebSocketWrapper;

namespace libsignalservice.websocket
{
    public class SignalWebSocketConnection
    {
        private static readonly string TAG = "WebSocketConnection";
        private static readonly int KEEPALIVE_TIMEOUT_SECONDS = 55;
        private static readonly Object obj = new Object();

        private readonly BlockingCollection<WebSocketRequestMessage> IncomingRequests = new BlockingCollection<WebSocketRequestMessage>(new ConcurrentQueue<WebSocketRequestMessage>());

        private readonly string wsUri;
        private readonly TrustStore trustStore;
        private readonly CredentialsProvider credentialsProvider;
        private readonly string userAgent;
        private WebSocketWrapper WebSocket;
        private CancellationToken Token;

        public SignalWebSocketConnection(CancellationToken token, string httpUri, TrustStore trustStore, CredentialsProvider credentialsProvider, string userAgent)
        {
            this.Token = token;
            this.trustStore = trustStore;
            this.credentialsProvider = credentialsProvider;
            this.userAgent = userAgent;
            this.wsUri = httpUri.Replace("https://", "wss://")
                .Replace("http://", "ws://") + $"/v1/websocket/?login={credentialsProvider.GetUser()}&password={credentialsProvider.GetPassword()}";
            this.userAgent = userAgent;
            WebSocket = new WebSocketWrapper(wsUri, token);
            WebSocket.OnConnect(Connection_OnOpened);
            WebSocket.OnMessage(Connection_OnMessage);
        }

        public void Connect()
        {
            Debug.WriteLine("WebSocketConnection: connect()...");
            WebSocket.Connect();
        }

        private void Connection_OnOpened()
        {
            Debug.WriteLine("WebSocketConnection: opened!");
        }

        private void Connection_OnMessage(byte[] obj)
        {
            var msg = WebSocketMessage.Parser.ParseFrom(obj);
            if(msg.Type == WebSocketMessage.Types.Type.Request)
            {
                IncomingRequests.Add(msg.Request);
            } else if(msg.Type == WebSocketMessage.Types.Type.Response)
            {
                Debug.WriteLine("SignalWebSocketConnection received response id={0}, message={1}, status={2} body={3}", msg.Response.Id, msg.Response.Message, msg.Response.Id, msg.Response.Body);
            }
        }

        public void Disconnect()
        {
            Debug.WriteLine("WebSocketConnection disconnect()...");
            throw new NotImplementedException();
        }

        public LinkedList<WebSocketRequestMessage> readRequests()
        {
            LinkedList<WebSocketRequestMessage> requests = new LinkedList<WebSocketRequestMessage>();

            WebSocketRequestMessage item;
            while (IncomingRequests.TryTake(out item))
            {
                requests.AddLast(item);
            }
            if(requests.Count > 0)
            {
                return requests;
            }
            requests.AddLast(IncomingRequests.Take(Token));
            return requests;
        }

        public void SendRequest(WebSocketRequestMessage request)
        {
            WebSocketMessage message = new WebSocketMessage
            {
                Type = WebSocketMessage.Types.Type.Request,
                Request = request
            };
            WebSocket.SendMessage(message.ToByteArray());
        }

        public void SendResponse(WebSocketResponseMessage response)
        {
            WebSocketMessage message = new WebSocketMessage
            {
                Type = WebSocketMessage.Types.Type.Response,
                Response = response
            };
            WebSocket.SendMessage(message.ToByteArray());
        }

        private void sendKeepAlive(CancellationToken token, object state)
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
            WebSocket.SendMessage( message.ToByteArray());

        }
    }
}
