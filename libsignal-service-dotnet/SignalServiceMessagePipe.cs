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
using System.Diagnostics;
using libsignalservice.messages;
using libsignalservice.push;
using libsignalservice.util;
using libsignalservice.websocket;
using System.Threading;
using Google.Protobuf;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IO;

namespace libsignalservice
{
    /// <summary>
    /// A SignalServiceMessagePipe represents a dedicated connection
    /// to the Signal Service server, which the server can push messages
    /// down through.
    /// </summary>
    public class SignalServiceMessagePipe
    {
        private const string TAG = "SignalServiceMessagePipe";
        private readonly SignalWebSocketConnection Websocket;
        private readonly CredentialsProvider CredentialsProvider;
        CancellationToken Token;

        public SignalServiceMessagePipe(CancellationToken token, SignalWebSocketConnection websocket, CredentialsProvider credentialsProvider)
        {
            this.Token = token;
            this.Websocket = websocket;
            this.CredentialsProvider = credentialsProvider;
            this.Websocket.Connect();
        }

        public void ReadBlocking(MessagePipeCallback callback)
        {
            LinkedList<WebSocketRequestMessage> requests = Websocket.readRequests();
            int amount = requests.Count;
            SignalServiceEnvelope[] envelopes = new SignalServiceEnvelope[amount];
            WebSocketResponseMessage[] responses = new WebSocketResponseMessage[amount];
            for(int i = 0;i<amount;i++)
            {
                WebSocketRequestMessage msg = requests.First.Value;
                requests.RemoveFirst();
                if (isSignalServiceEnvelope(msg))
                {
                    envelopes[i] = new SignalServiceEnvelope(msg.Body.ToByteArray(), CredentialsProvider.GetSignalingKey());
                    responses[i] = createWebSocketResponse(msg);
                }
            }
            try
            {
                callback.onMessages(envelopes);
            }
            finally
            {
                foreach(WebSocketResponseMessage response in responses)
                {
                    Websocket.SendResponse(response);
                }              
            }
        }

        public void Send(OutgoingPushMessageList list)
        {
            WebSocketRequestMessage requestmessage = new WebSocketRequestMessage() {
                Id = BitConverter.ToUInt64(Util.getSecretBytes(sizeof(long)), 0),
                Verb = "PUT",
                Path = $"/v1/messages/{list.getDestination()}",
                Body = ByteString.CopyFrom(Encoding.UTF8.GetBytes(JsonUtil.toJson(list)))
            };
            requestmessage.Headers.Add("content-type:application/json");
            var t = Websocket.SendRequest(requestmessage);
            t.Wait();
            if(t.IsCompleted)
            {
                var response = t.Result;
                if(response.Item1 < 200 || response.Item1 >= 300)
                {
                    throw new IOException("non-successfull response: " + response.Item1 + " " + response.Item2);
                }
            }
            else
            {
                throw new IOException("timeout reached while waiting for confirmation");
            }
        }

        /// <summary>
        /// Close this connection to the server.
        /// </summary>
        public void Shutdown()
        {
            Websocket.Disconnect();
        }

        private bool isSignalServiceEnvelope(WebSocketRequestMessage message)
        {
            return "PUT".Equals(message.Verb) && "/api/v1/message".Equals(message.Path);
        }

        private WebSocketResponseMessage createWebSocketResponse(WebSocketRequestMessage request)
        {
            if (isSignalServiceEnvelope(request))
            {
                return new WebSocketResponseMessage
                {
                    Id = request.Id,
                    Status = 200,
                    Message = "OK"
                };
            }
            else
            {
                return new WebSocketResponseMessage
                {
                    Id = request.Id,
                    Status = 400,
                    Message = "Unknown"
                };
            }
        }
      
        /**
         * For receiving a callback when a new message has been
         * received.
         */
        public interface MessagePipeCallback
        {
            void onMessages(SignalServiceEnvelope[] envelopes);
        }
    }
}
