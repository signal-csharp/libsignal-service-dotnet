using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Google.Protobuf;
using libsignalservice.messages;
using libsignalservice.profiles;
using libsignalservice.push;
using libsignalservice.util;
using libsignalservice.websocket;
using libsignalservicedotnet.crypto;
using Microsoft.Extensions.Logging;

namespace libsignalservice
{
    /// <summary>
    /// A SignalServiceMessagePipe represents a dedicated connection
    /// to the Signal Service server, which the server can push messages
    /// down through.
    /// </summary>
    public class SignalServiceMessagePipe
    {
        private readonly ILogger Logger = LibsignalLogging.CreateLogger<SignalServiceMessagePipe>();
        private readonly ISignalWebSocketFactory SignalWebSocketFactory;
        private readonly SignalWebSocketConnection Websocket;
        private readonly ICredentialsProvider? CredentialsProvider;
        private CancellationToken Token;

        internal SignalServiceMessagePipe(CancellationToken token, SignalWebSocketConnection websocket,
            ICredentialsProvider? credentialsProvider, ISignalWebSocketFactory webSocketFactory)
        {
            Logger.LogTrace("SignalServiceMessagePipe()");
            Token = token;
            Websocket = websocket;
            CredentialsProvider = credentialsProvider;
            SignalWebSocketFactory = webSocketFactory;
        }

        /// <summary>
        /// Connect message pipe.
        /// </summary>
        /// <returns>Task</returns>
        public async Task Connect()
        {
            Logger.LogTrace("Connecting to message pipe");
            await Websocket.Connect();
        }

        /// <summary>
        /// Blocks until a message was received, calls the IMessagePipeCallback and confirms the message to the server, unless the pipe's token is canceled.
        /// </summary>
        /// <param name="callback"></param>
        public async Task ReadBlocking(IMessagePipeCallback callback)
        {
            Logger.LogTrace("ReadBlocking()");
            if (CredentialsProvider == null)
            {
                throw new ArgumentException("You can't read messages if you haven't specified credentials");
            }
            WebSocketRequestMessage request = Websocket.ReadRequestBlocking();

            if (IsSignalServiceEnvelope(request))
            {
                SignalServiceMessagePipeMessage message = new SignalServiceEnvelope(request.Body.ToByteArray());
                WebSocketResponseMessage response = CreateWebSocketResponse(request);
                try
                {
                    Logger.LogDebug("Calling callback with message {0}", request.Id);
                    await callback.OnMessage(message);
                }
                finally
                {
                    if (!Token.IsCancellationRequested)
                    {
                        Logger.LogDebug("Confirming message {0}", request.Id);
                        Websocket.SendResponse(response);
                    }
                }
            }
            else if (IsPipeEmptyMessage(request))
            {
                Logger.LogInformation("Calling callback with SignalServiceMessagePipeEmptyMessage");
                await callback.OnMessage(new SignalServiceMessagePipeEmptyMessage());
            }
            else
            {
                Logger.LogWarning("Unknown request: {0} {1}", request.Verb, request.Path);
            }
        }

        /// <summary>
        /// Sends a message through the pipe. Blocks until delivery is confirmed or throws an IOException if a timeout occurs.
        /// </summary>
        /// <param name="list"></param>
        /// <param name="unidentifiedAccess"></param>
        /// <returns></returns>
        public async Task<SendMessageResponse> Send(OutgoingPushMessageList list, UnidentifiedAccess? unidentifiedAccess)
        {
            Logger.LogTrace("Send()");
            var headers = new List<string>()
            {
                "content-type:application/json"
            };
            if (unidentifiedAccess != null)
            {
                headers.Add("Unidentified-Access-Key:" + Base64.EncodeBytes(unidentifiedAccess.UnidentifiedAccessKey));
            }
            WebSocketRequestMessage requestmessage = new WebSocketRequestMessage()
            {
                Id = BitConverter.ToUInt64(Util.GetSecretBytes(sizeof(long)), 0),
                Verb = "PUT",
                Path = $"/v1/messages/{list.Destination}",
                Body = ByteString.CopyFrom(Encoding.UTF8.GetBytes(JsonUtil.ToJson(list)))
            };
            requestmessage.Headers.AddRange(headers);
            var sendTask = (await Websocket.SendRequest(requestmessage)).Task;
            var timerCancelSource = new CancellationTokenSource();
            if (await Task.WhenAny(sendTask, Task.Delay(10*1000, timerCancelSource.Token)) == sendTask)
            {
                timerCancelSource.Cancel();
                var (Status, Body) = sendTask.Result;
                if (Status < 200 || Status >= 300)
                {
                    throw new IOException("non-successful response: " + Status);
                }
                if (Util.IsEmpty(Body))
                    return new SendMessageResponse(false);
                return JsonUtil.FromJson<SendMessageResponse>(Body);
            }
            else
            {
                Logger.LogError("Sending message {0} failed: timeout", requestmessage.Id);
                throw new IOException("timeout reached while waiting for confirmation");
            }
        }

        /// <summary>
        /// Fetches a profile from the server. Blocks until the response arrives or a timeout occurs.
        /// </summary>
        /// <param name="address"></param>
        /// <param name="unidentifiedAccess"></param>
        /// <returns></returns>
        public async Task<SignalServiceProfile> GetProfile(SignalServiceAddress address, UnidentifiedAccess? unidentifiedAccess)
        {
            Logger.LogTrace("GetProfile()");
            var headers = new List<string>()
            {
                "content-type:application/json"
            };
            if (unidentifiedAccess != null)
            {
                headers.Add("Unidentified-Access-Key:" + Base64.EncodeBytes(unidentifiedAccess.UnidentifiedAccessKey));
            }
            WebSocketRequestMessage requestMessage = new WebSocketRequestMessage()
            {
                Id = BitConverter.ToUInt64(Util.GetSecretBytes(sizeof(long)), 0),
                Verb = "GET",
                Path = $"/v1/profile/{address.GetIdentifier()}"
            };

            var sendTask = (await Websocket.SendRequest(requestMessage)).Task;
            var timerCancelSource = new CancellationTokenSource();
            if (await Task.WhenAny(sendTask, Task.Delay(TimeSpan.FromSeconds(10), timerCancelSource.Token)) == sendTask)
            {
                timerCancelSource.Cancel();
                var (Status, Body) = sendTask.Result;
                if (Status < 200 || Status >= 300)
                {
                    throw new IOException("non-successful response: " + Status);
                }
                return JsonUtil.FromJson<SignalServiceProfile>(Body);
            }
            else
            {
                throw new IOException("timeout reached while waiting for profile");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<AttachmentV2UploadAttributes> GetAttachmentV2UploadAttributesAsync()
        {
            WebSocketRequestMessage requestMessage = new WebSocketRequestMessage()
            {
                Id = BitConverter.ToUInt64(Util.GetSecretBytes(sizeof(long)), 0),
                Verb = "GET",
                Path = "/v2/attachments/form/upload"
            };

            var sendTask = (await Websocket.SendRequest(requestMessage)).Task;
            var timerCancelSource = new CancellationTokenSource();
            if (await Task.WhenAny(sendTask, Task.Delay(TimeSpan.FromSeconds(10), timerCancelSource.Token)) == sendTask)
            {
                timerCancelSource.Cancel();
                var (status, body) = sendTask.Result;
                if (status < 200 || status >= 300)
                {
                    throw new IOException($"Non-successful response: {status}");
                }

                return JsonUtil.FromJson<AttachmentV2UploadAttributes>(body);
            }
            else
            {
                throw new IOException("Timeout reached while waiting for attachment upload attributes.");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<AttachmentV3UploadAttributes> GetAttachmentV3UploadAttributesAsync()
        {
            WebSocketRequestMessage requestMessage = new WebSocketRequestMessage()
            {
                Id = BitConverter.ToUInt64(Util.GetSecretBytes(sizeof(long)), 0),
                Verb = "GET",
                Path = "/v3/attachments/form/upload"
            };

            var sendTask = (await Websocket.SendRequest(requestMessage)).Task;
            var timerCancelSource = new CancellationTokenSource();
            if (await Task.WhenAny(sendTask, Task.Delay(TimeSpan.FromSeconds(10), timerCancelSource.Token)) == sendTask)
            {
                timerCancelSource.Cancel();
                var (status, body) = sendTask.Result;
                if (status < 200 || status >= 300)
                {
                    throw new IOException($"Non-successful response: {status}");
                }

                return JsonUtil.FromJson<AttachmentV3UploadAttributes>(body);
            }
            else
            {
                throw new IOException("Timeout reached while waiting for attachment upload attributes.");
            }
        }

        /// <summary>
        /// Close this connection to the server.
        /// </summary>
        public void Shutdown()
        {
            Websocket.Disconnect();
        }

        private bool IsSignalServiceEnvelope(WebSocketRequestMessage message)
        {
            return message.Verb == "PUT" && message.Path == "/api/v1/message";
        }

        private bool IsPipeEmptyMessage(WebSocketRequestMessage message)
        {
            return message.Verb == "PUT" && message.Path == "/api/v1/queue/empty";
        }

        private WebSocketResponseMessage CreateWebSocketResponse(WebSocketRequestMessage request)
        {
            if (IsSignalServiceEnvelope(request))
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

        /// <summary>
        ///    Abstract superclass for messages received via the SignalServiceMessagePipe.
        /// </summary>
        public abstract class SignalServiceMessagePipeMessage
        {

        }
        /// <summary>
        /// A Message that indicates that the queue is empty.
        /// </summary>
        public class SignalServiceMessagePipeEmptyMessage: SignalServiceMessagePipeMessage
        {

        }

        /// <summary>
        /// A callback interface for the message pipe.
        /// </summary>
        public interface IMessagePipeCallback
        {
            /// <summary>
            /// This message is called for every message received via the pipe.
            /// </summary>
            /// <param name="message">The received message</param>
            Task OnMessage(SignalServiceMessagePipeMessage message);
        }
    }
}
