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

        private readonly WebSocketConnection websocket;
        private readonly CredentialsProvider credentialsProvider;

        //public event TypedEventHandler<SignalServiceMessagePipe, SignalServiceEnvelope> MessageReceived;

        public SignalServiceMessagePipe(WebSocketConnection websocket, CredentialsProvider credentialsProvider)
        {
            this.websocket = websocket;

            //this.websocket.MessageReceived += OnMessageReceived; //TODO
            this.credentialsProvider = credentialsProvider;

            this.websocket.connect();
        }

        private void OnMessageReceived(WebSocketConnection sender, WebSocketRequestMessage request)
        {
            WebSocketResponseMessage response = createWebSocketResponse(request);

            Debug.WriteLine($"Verb: {request.Verb}, Path {request.Path}, Body({request.Body.Length}): {request.Body}, Id: {request.Id}");

            try
            {
                if (isSignalServiceEnvelope(request))
                {
                    SignalServiceEnvelope envelope = new SignalServiceEnvelope(request.Body.ToByteArray(),
                                                                         credentialsProvider.GetSignalingKey());

                    //MessageReceived(this, envelope);
                }
            }
            //catch (Exception e) { } // ignore for now
            finally
            {
                websocket.sendResponse(response);
            }
        }

        public SendMessageResponse send(OutgoingPushMessageList list)
        {
            throw new NotImplementedException();
            //try
            //{
            //    WebSocketRequestMessage requestmessage = WebSocketRequestMessage.CreateBuilder()
            //        .SetId((ulong)CryptographicBuffer.GenerateRandomNumber())
            //        .SetVerb("PUT")
            //        .SetPath($"/v1/messages/{list.getDestination()}")
            //        .AddHeaders("content-type:application/json")
            //        .SetBody(ByteString.CopyFrom(Encoding.UTF8.GetBytes(JsonUtil.toJson(list))))
            //        .Build();

            //}
        }

        /// <summary>
        /// Close this connection to the server.
        /// </summary>
        public void shutdown()
        {
            websocket.disconnect();
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
        /*public interface MessagePipeCallback
        {
            void onMessage(TextSecureEnvelope envelope);
        }

        private class NullMessagePipeCallback : MessagePipeCallback
        {

            public void onMessage(TextSecureEnvelope envelope) { }
        }*/

    }
}
