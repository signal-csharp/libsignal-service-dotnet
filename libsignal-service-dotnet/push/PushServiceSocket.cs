using libsignal;
using libsignal.ecc;
using libsignal.push;
using libsignal.state;
using libsignal_service_dotnet.messages.calls;
using libsignaldotnet.push.http;
using libsignalservice.configuration;
using libsignalservice.crypto;
using libsignalservice.messages.multidevice;
using libsignalservice.profiles;
using libsignalservice.push.exceptions;
using libsignalservice.util;
using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static libsignalservice.messages.SignalServiceAttachment;

namespace libsignalservice.push
{
    internal class PushServiceSocket
    {
        private static readonly string TAG = "PushServiceSocket";
        private static readonly string CREATE_ACCOUNT_SMS_PATH = "/v1/accounts/sms/code/{0}";
        private static readonly string CREATE_ACCOUNT_VOICE_PATH = "/v1/accounts/voice/code/{0}";
        private static readonly string VERIFY_ACCOUNT_CODE_PATH = "/v1/accounts/code/{0}";
        private static readonly string REGISTER_GCM_PATH = "/v1/accounts/gcm/";
        private static readonly string TURN_SERVER_INFO = "/v1/accounts/turn";
        private static readonly string SET_ACCOUNT_ATTRIBUTES = "/v1/accounts/attributes";
        private static readonly String PIN_PATH = "/v1/accounts/pin/";

        private static readonly string PREKEY_METADATA_PATH = "/v2/keys/";
        private static readonly string PREKEY_PATH = "/v2/keys/{0}";
        private static readonly string PREKEY_DEVICE_PATH = "/v2/keys/{0}/{1}";
        private static readonly string SIGNED_PREKEY_PATH = "/v2/keys/signed";

        private static readonly string PROVISIONING_CODE_PATH = "/v1/devices/provisioning/code";
        private static readonly string PROVISIONING_MESSAGE_PATH = "/v1/provisioning/{0}";
        private static readonly string DEVICE_PATH = "/v1/devices/{0}";

        private static readonly string DIRECTORY_TOKENS_PATH = "/v1/directory/tokens";
        private static readonly string DIRECTORY_VERIFY_PATH = "/v1/directory/{0}";
        private static readonly string MESSAGE_PATH = "/v1/messages/{0}";
        private static readonly string ACKNOWLEDGE_MESSAGE_PATH = "/v1/messages/{0}/{1}";
        private static readonly string ATTACHMENT_PATH = "/v1/attachments/{0}";

        private static readonly string PROFILE_PATH = "/v1/profile/%s";

        private readonly SignalServiceConfiguration SignalConnectionInformation;
        private readonly CredentialsProvider CredentialsProvider;
        private readonly string UserAgent;

        public PushServiceSocket(SignalServiceConfiguration serviceUrls, CredentialsProvider credentialsProvider, string userAgent, X509Certificate2 server_cert=null)
        {
#if NETCOREAPP2_1
            if (server_cert != null)
                server_cert_raw = server_cert.GetRawCertData();
#endif
            CredentialsProvider = credentialsProvider;
            UserAgent = userAgent;
            SignalConnectionInformation = serviceUrls;
        }

        public bool CreateAccount(bool voice)
        {
            string path = voice ? CREATE_ACCOUNT_VOICE_PATH : CREATE_ACCOUNT_SMS_PATH;
            MakeServiceRequest(string.Format(path, CredentialsProvider.User), "GET", null);
            return true;
        }

        public bool VerifyAccountCode(string verificationCode, string signalingKey, uint registrationId, bool fetchesMessages, string pin)
        {
            AccountAttributes signalingKeyEntity = new AccountAttributes(signalingKey, registrationId, fetchesMessages, pin);
            MakeServiceRequest(string.Format(VERIFY_ACCOUNT_CODE_PATH, verificationCode), "PUT", JsonUtil.ToJson(signalingKeyEntity));
            return true;
        }

        public bool SetAccountAttributes(string signalingKey, uint registrationId, bool fetchesMessages, string pin)
        {
            AccountAttributes accountAttributesEntity = new AccountAttributes(signalingKey, registrationId, fetchesMessages, pin);
            MakeServiceRequest(SET_ACCOUNT_ATTRIBUTES, "PUT", JsonUtil.ToJson(accountAttributesEntity));
            return true;
        }

        public async Task<int> FinishNewDeviceRegistration(CancellationToken token, String code, String signalingKey, bool supportsSms, bool fetchesMessages, int registrationId, String deviceName)
        {
            ConfirmCodeMessage javaJson = new ConfirmCodeMessage(signalingKey, supportsSms, fetchesMessages, registrationId, deviceName);
            string json = JsonUtil.ToJson(javaJson);
            string responseText = await MakeServiceRequestAsync(token, string.Format(DEVICE_PATH, code), "PUT", json);
            DeviceId response = JsonUtil.FromJson<DeviceId>(responseText);
            return response.NewDeviceId;
        }

        public string GetNewDeviceVerificationCode()// throws IOException
        {
            string responseText = MakeServiceRequest(PROVISIONING_CODE_PATH, "GET", null);
            return JsonUtil.FromJson<DeviceCode>(responseText).VerificationCode;
        }

        public bool SendProvisioningMessage(string destination, byte[] body)// throws IOException
        {
            MakeServiceRequest(string.Format(PROVISIONING_MESSAGE_PATH, destination), "PUT",
                    JsonUtil.ToJson(new ProvisioningMessage(Base64.EncodeBytes(body))));
            return true;
        }

        public List<DeviceInfo> GetDevices()// throws IOException
        {
            string responseText = MakeServiceRequest(string.Format(DEVICE_PATH, ""), "GET", null);
            return JsonUtil.FromJson<DeviceInfoList>(responseText).Devices;
        }

        public bool RemoveDevice(long deviceId)// throws IOException
        {
            MakeServiceRequest(string.Format(DEVICE_PATH, deviceId), "DELETE", null);
            return true;
        }

        public void RegisterGcmId(String gcmRegistrationId)
        {
            GcmRegistrationId registration = new GcmRegistrationId(gcmRegistrationId, true);
            MakeServiceRequest(REGISTER_GCM_PATH, "PUT", JsonUtil.ToJson(registration));
        }

        public void UnregisterGcmId()
        {
            MakeServiceRequest(REGISTER_GCM_PATH, "DELETE", null);
        }

        public void SetPin(string pin)
        {
            RegistrationLock accountLock = new RegistrationLock(pin);
            MakeServiceRequest(PIN_PATH, "PUT", JsonUtil.ToJson(accountLock));
        }

        public void RemovePin()
        {
            MakeServiceRequest(PIN_PATH, "PUT", null);
        }

        public SendMessageResponse SendMessage(OutgoingPushMessageList bundle)
        {
            try
            {
                string responseText = MakeServiceRequest(string.Format(MESSAGE_PATH, bundle.Destination), "PUT", JsonUtil.ToJson(bundle));
                return JsonUtil.FromJson<SendMessageResponse>(responseText);
            }
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(bundle.Destination, nfe);
            }
        }

        public List<SignalServiceEnvelopeEntity> GetMessages()// throws IOException
        {
            string responseText = MakeServiceRequest(string.Format(MESSAGE_PATH, ""), "GET", null);
            return JsonUtil.FromJson<SignalServiceEnvelopeEntityList>(responseText).Messages;
        }

        public bool AcknowledgeMessage(string sender, ulong timestamp)// throws IOException
        {
            MakeServiceRequest(string.Format(ACKNOWLEDGE_MESSAGE_PATH, sender, timestamp), "DELETE", null);
            return true;
        }

        public bool RegisterPreKeys(IdentityKey identityKey,
                                    SignedPreKeyRecord signedPreKey,
                                    IList<PreKeyRecord> records)
        //throws IOException
        {
            List<PreKeyEntity> entities = new List<PreKeyEntity>();

            foreach (PreKeyRecord record in records)
            {
                PreKeyEntity entity = new PreKeyEntity(record.getId(),
                                                       record.getKeyPair().getPublicKey());

                entities.Add(entity);
            }

            SignedPreKeyEntity signedPreKeyEntity = new SignedPreKeyEntity(signedPreKey.getId(),
                                                                   signedPreKey.getKeyPair().getPublicKey(),
                                                                   signedPreKey.getSignature());

            MakeServiceRequest(string.Format(PREKEY_PATH, ""), "PUT",
                JsonUtil.ToJson(new PreKeyState(entities, signedPreKeyEntity, identityKey)));
            return true;
        }

        public int GetAvailablePreKeys()// throws IOException
        {
            string responseText = MakeServiceRequest(PREKEY_METADATA_PATH, "GET", null);
            PreKeyStatus preKeyStatus = JsonUtil.FromJson<PreKeyStatus>(responseText);

            return preKeyStatus.Count;
        }

        public List<PreKeyBundle> GetPreKeys(SignalServiceAddress destination, uint deviceIdInteger)// throws IOException
        {
            try
            {
                string deviceId = deviceIdInteger.ToString();

                if (deviceId.Equals("1"))
                    deviceId = "*";

                string path = string.Format(PREKEY_DEVICE_PATH, destination.E164number, deviceId);

                if (destination.Relay != null)
                {
                    path = path + "?relay=" + destination.Relay;
                }

                string responseText = MakeServiceRequest(path, "GET", null);
                PreKeyResponse response = JsonUtil.FromJson<PreKeyResponse>(responseText);
                List<PreKeyBundle> bundles = new List<PreKeyBundle>();

                foreach (PreKeyResponseItem device in response.Devices)
                {
                    ECPublicKey preKey = null;
                    ECPublicKey signedPreKey = null;
                    byte[] signedPreKeySignature = null;
                    int preKeyId = -1;
                    int signedPreKeyId = -1;

                    if (device.SignedPreKey != null)
                    {
                        signedPreKey = device.SignedPreKey.PublicKey;
                        signedPreKeyId = (int)device.SignedPreKey.KeyId;
                        signedPreKeySignature = device.SignedPreKey.Signature;
                    }

                    if (device.PreKey != null)
                    {
                        preKeyId = (int)device.PreKey.KeyId;
                        preKey = device.PreKey.PublicKey;
                    }

                    bundles.Add(new PreKeyBundle(device.RegistrationId, device.DeviceId, (uint)preKeyId,
                                                         preKey, (uint)signedPreKeyId, signedPreKey, signedPreKeySignature,
                                                         response.IdentityKey));
                }

                return bundles;
            }
            /*catch (JsonUtil.JsonParseException e)
            {
                throw new IOException(e);
            }*/
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(destination.E164number, nfe);
            }
        }

        public PreKeyBundle GetPreKey(SignalServiceAddress destination, uint deviceId)// throws IOException
        {
            try
            {
                string path = string.Format(PREKEY_DEVICE_PATH, destination.E164number,
                                            deviceId.ToString());

                if (destination.Relay != null)
                {
                    path = path + "?relay=" + destination.Relay;
                }

                string responseText = MakeServiceRequest(path, "GET", null);
                PreKeyResponse response = JsonUtil.FromJson<PreKeyResponse>(responseText);

                if (response.Devices == null || response.Devices.Count < 1)
                    throw new Exception("Empty prekey list");

                PreKeyResponseItem device = response.Devices[0];
                ECPublicKey preKey = null;
                ECPublicKey signedPreKey = null;
                byte[] signedPreKeySignature = null;
                int preKeyId = -1;
                int signedPreKeyId = -1;

                if (device.PreKey != null)
                {
                    preKeyId = (int)device.PreKey.KeyId;
                    preKey = device.PreKey.PublicKey;
                }

                if (device.SignedPreKey != null)
                {
                    signedPreKeyId = (int)device.SignedPreKey.KeyId;
                    signedPreKey = device.SignedPreKey.PublicKey;
                    signedPreKeySignature = device.SignedPreKey.Signature;
                }

                return new PreKeyBundle(device.RegistrationId, device.DeviceId, (uint)preKeyId, preKey,
                                        (uint)signedPreKeyId, signedPreKey, signedPreKeySignature, response.IdentityKey);
            }
            /*catch (JsonUtil.JsonParseException e)
            {
                throw new IOException(e);
            }*/
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(destination.E164number, nfe);
            }
        }

        public SignedPreKeyEntity GetCurrentSignedPreKey()// throws IOException
        {
            try
            {
                string responseText = MakeServiceRequest(SIGNED_PREKEY_PATH, "GET", null);
                return JsonUtil.FromJson<SignedPreKeyEntity>(responseText);
            }
            catch (/*NotFound*/Exception e)
            {
                Debug.WriteLine(e.Message, TAG);
                return null;
            }
        }

        public bool SetCurrentSignedPreKey(SignedPreKeyRecord signedPreKey)// throws IOException
        {
            SignedPreKeyEntity signedPreKeyEntity = new SignedPreKeyEntity(signedPreKey.getId(),
                                                                           signedPreKey.getKeyPair().getPublicKey(),
                                                                           signedPreKey.getSignature());
            MakeServiceRequest(SIGNED_PREKEY_PATH, "PUT", JsonUtil.ToJson(signedPreKeyEntity));
            return true;
        }

        public (ulong id, byte[] digest) SendAttachment(PushAttachmentData attachment)// throws IOException
        {
            var (id, location) = RetrieveAttachmentUploadUrl();

            byte[] digest = UploadAttachment("PUT", location, attachment.Data,
                attachment.DataSize, attachment.OutputFactory, attachment.Listener);

            return (id, digest);
        }

        /// <summary>
        /// Gets a URL that can be used to upload an attachment
        /// </summary>
        /// <returns>The attachment ID and the URL</returns>
        public (ulong id, string location) RetrieveAttachmentUploadUrl()
        {
            string response = MakeServiceRequest(string.Format(ATTACHMENT_PATH, ""), "GET", null);
            AttachmentDescriptor attachmentKey = JsonUtil.FromJson<AttachmentDescriptor>(response);

            if (attachmentKey == null || attachmentKey.Location == null)
            {
                throw new Exception("Server failed to allocate an attachment key!");
            }

            Debug.WriteLine("Got attachment content location: " + attachmentKey.Location, TAG);
            return (attachmentKey.Id, attachmentKey.Location);
        }

        public void RetrieveAttachment(string relay, ulong attachmentId, Stream tmpDestination, int maxSizeBytes)
        {
            string attachmentUrlLocation = RetrieveAttachmentDownloadUrl(relay, attachmentId);
            DownloadAttachment(attachmentUrlLocation, tmpDestination);
        }

        /// <summary>
        /// Gets the URL location of an attachment
        /// </summary>
        /// <param name="relay"></param>
        /// <param name="attachmentId"></param>
        /// <returns></returns>
        public string RetrieveAttachmentDownloadUrl(string relay, ulong attachmentId)
        {
            string path = string.Format(ATTACHMENT_PATH, attachmentId.ToString());

            if (!Util.IsEmpty(relay))
            {
                path = path + "?relay=" + relay;
            }

            string response = MakeServiceRequest(path, "GET", null);
            Debug.WriteLine("PushServiceSocket: Received resp " + response);
            AttachmentDescriptor descriptor = JsonUtil.FromJson<AttachmentDescriptor>(response);
            Debug.WriteLine("PushServiceSocket: Attachment: " + attachmentId + " is at: " + descriptor.Location);
            return descriptor.Location;
        }

        public SignalServiceProfile RetrieveProfile(SignalServiceAddress target)
        {
            try
            {
                string response = MakeServiceRequest(string.Format(PROFILE_PATH, target.E164number), "GET", null);
                return JsonUtil.FromJson<SignalServiceProfile>(response);
            }
            catch (Exception e)
            {
                throw new NonSuccessfulResponseCodeException("Unable to parse entity: "+e.Message);
            }
        }

        public void RetrieveProfileAvatar(string path, FileStream destination, int maxSizeByzes)
        {
            DownloadFromCdn(destination, path, maxSizeByzes);
        }

        public void SetProfileName(string name)
        {
            MakeServiceRequest(string.Format(PROFILE_PATH, "name/" + (name == null ? "" : WebUtility.UrlEncode(name))), "PUT", "");
        }

        public void SetProfileAvatar(ProfileAvatarData profileAvatar)
        {
            String response = MakeServiceRequest(string.Format(PROFILE_PATH, "form/avatar"), "GET", null);
            ProfileAvatarUploadAttributes formAttributes;

            try
            {
                formAttributes = JsonUtil.FromJson<ProfileAvatarUploadAttributes>(response);
            }
            catch (IOException e)
            {
                throw new NonSuccessfulResponseCodeException("Unable to parse entity ("+e.Message+")");
            }

            if (profileAvatar != null) {
                UploadToCdn(formAttributes.Acl, formAttributes.Key,
                    formAttributes.Policy, formAttributes.Algorithm,
                    formAttributes.Credential, formAttributes.Date,
                    formAttributes.Signature, profileAvatar.InputData,
                    profileAvatar.ContentType, profileAvatar.DataLength,
                    profileAvatar.OutputStreamFactory);
            }
        }

        private void DownloadFromCdn(Stream destination, string path, int maxSizeBytes)
        {
            SignalUrl signalUrl = GetRandom(SignalConnectionInformation.SignalCdnUrls);
            string url = signalUrl.Url;
            string hostHeader = signalUrl.HostHeader;
            throw new NotImplementedException(); //TODO
        }

        private void UploadToCdn(string acl, string key, string policy, string algorithm, string credential, string date,
            string signature, Stream inputData, string contentType, long dataLength, OutputStreamFactory outputStreamFactory)
        {
            SignalUrl signalUrl = GetRandom(SignalConnectionInformation.SignalCdnUrls);
            string url = signalUrl.Url;
            string hostHeader = signalUrl.HostHeader;
            throw new NotImplementedException(); //TODO
        }

        public List<ContactTokenDetails> RetrieveDirectory(ICollection<string> contactTokens) // TODO: whacky
                                                                                              //throws NonSuccessfulResponseCodeException, PushNetworkException
        {
            LinkedList<HashSet<string>> temp = new LinkedList<HashSet<string>>();
            ContactTokenList contactTokenList = new ContactTokenList(contactTokens.ToList());
            string response = MakeServiceRequest(DIRECTORY_TOKENS_PATH, "PUT", JsonUtil.ToJson(contactTokenList));
            ContactTokenDetailsList activeTokens = JsonUtil.FromJson<ContactTokenDetailsList>(response);

            return activeTokens.Contacts;
        }

        public ContactTokenDetails GetContactTokenDetails(string contactToken)// throws IOException
        {
            try
            {
                string response = MakeServiceRequest(string.Format(DIRECTORY_VERIFY_PATH, contactToken), "GET", null);
                return JsonUtil.FromJson<ContactTokenDetails>(response);
            }
            catch (Exception)
            {
                return null;
            }
        }

        public async Task<TurnServerInfo> GetTurnServerInfo(CancellationToken token)
        {
            string response = await MakeServiceRequestAsync(token, TURN_SERVER_INFO, "GET", null);
            return JsonUtil.FromJson<TurnServerInfo>(response);
        }

        public void SetSoTimeoutMillis(long soTimeoutMillis)
        {
            throw new NotImplementedException();
        }

        public void CancelInFlightRequests()
        {
            throw new NotImplementedException();
        }

        private void DownloadAttachment(string url, Stream localDestination)
        {
            try
            {
                HttpClient connection = new HttpClient();
                var headers = connection.DefaultRequestHeaders;
                Debug.WriteLine("downloading " + url);
                HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Content = new StringContent("");
                req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                using (var resp = connection.SendAsync(req).Result)
                {
                    Stream input = resp.Content.ReadAsStreamAsync().Result;
                    byte[] buffer = new byte[4096];
                    int read = 0;
                    while (true)
                    {
                        read = input.Read(buffer, 0, 4096);
                        if (read == 0)
                        {
                            Debug.WriteLine("PushServiceSocket Downloaded: " + url + " to: " + localDestination);
                            localDestination.Flush();
                            return;
                        }
                        localDestination.Write(buffer, 0, read);
                    }
                }
            }
            catch (Exception ioe)
            {
                Debug.WriteLine(ioe.Message);
                Debug.WriteLine(ioe.StackTrace);
                throw new PushNetworkException(ioe);
            }
        }

        private byte[] UploadAttachment(string method, string url, Stream data, long dataSize,
            OutputStreamFactory outputStreamFactory, IProgressListener listener)
        {
            MemoryStream tmpStream = new MemoryStream();
            DigestingOutputStream outputStream = outputStreamFactory.CreateFor(tmpStream);
            StreamContent streamContent = new StreamContent(tmpStream);
            var request = new HttpRequestMessage(HttpMethod.Put, url);
            request.Content = streamContent;
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            request.Headers.ConnectionClose = true;

            HttpClient client = new HttpClient();
            HttpResponseMessage response = client.SendAsync(request).Result;
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new IOException($"Bad response: {response.StatusCode} {response.Content.ReadAsStringAsync().Result}");
            }

            return outputStream.GetTransmittedDigest();
        }

        /// <summary>
        /// Encrypts an attachment to be uploaded
        /// </summary>
        /// <param name="data">The data stream of the attachment</param>
        /// <param name="key">64 random bytes</param>
        /// <returns>The digest and the encrypted data</returns>
        public (byte[] digest, Stream encryptedData) EncryptAttachment(Stream data, byte[] key)
        {
            // This stream will hold the encrypted data
            MemoryStream memoryStream = new MemoryStream();

            // This is the final digest
            byte[] digest = new byte[0];

            byte[][] keyParts = Util.Split(key, 32, 32);
            using (var mac = new HMACSHA256())
            {
                using (var cipher = Aes.Create())
                {
                    cipher.Key = keyParts[0];
                    cipher.Mode = CipherMode.CBC;
                    cipher.Padding = PaddingMode.PKCS7;
                    mac.Key = keyParts[1];

                    // First write the IV to the memory stream
                    memoryStream.Write(cipher.IV, 0, cipher.IV.Length);
                    using (var encrypt = cipher.CreateEncryptor())
                    using (var cryptoStream = new CryptoStream(memoryStream, encrypt, CryptoStreamMode.Write))
                    {
                        // Then read from the data stream and write it to the crypto stream
                        byte[] buffer = new byte[4096];
                        int read = data.Read(buffer, 0, buffer.Length);
                        while (read > 0)
                        {
                            cryptoStream.Write(buffer, 0, read);
                            read = data.Read(buffer, 0, buffer.Length);
                        }
                        cryptoStream.Flush();
                        cryptoStream.FlushFinalBlock();

                        // Then hash the stream and write the hash to the end
                        memoryStream.Seek(0, SeekOrigin.Begin);
                        byte[] auth = mac.ComputeHash(memoryStream);
                        memoryStream.Write(auth, 0, auth.Length);

                        // Then get the digest of the entire file
                        using (SHA256 sha = SHA256.Create())
                        {
                            memoryStream.Seek(0, SeekOrigin.Begin);
                            digest = sha.ComputeHash(memoryStream);
                        }
                    }
                }
            }

            // The crypto stream closed the stream so we need to make a new one
            MemoryStream encryptedData = new MemoryStream(memoryStream.ToArray());
            return (digest, encryptedData);
        }

        private string MakeServiceRequest(string urlFragment, string method, string body)
        {
            try
            {
                var dummy = new CancellationTokenSource();
                return MakeServiceRequestAsync(dummy.Token, urlFragment, method, body).Result;
            }
            catch (AggregateException e)
            {
                throw e.InnerException;
            }
        }

        private async Task<string> MakeServiceRequestAsync(CancellationToken token, string urlFragment, string method, string body)
        //throws NonSuccessfulResponseCodeException, PushNetworkException
        {
            HttpResponseMessage connection = await GetServiceConnectionAsync(token, urlFragment, method, body);
            HttpStatusCode responseCode;
            string responseMessage;
            string responseBody;

            try
            {
                responseCode = connection.StatusCode;
                responseMessage = connection.ReasonPhrase;
                responseBody = await connection.Content.ReadAsStringAsync();
            }
            catch (Exception ioe)
            {
                Debug.WriteLine(ioe.Message);
                Debug.WriteLine(ioe.StackTrace);
                throw new PushNetworkException(ioe);
            }

            switch ((uint)responseCode)
            {
                case 413: // HttpStatusCode.RequestEntityTooLarge
                    throw new RateLimitException("Rate limit exceeded: " + responseCode);
                case 401: // HttpStatusCode.Unauthorized
                case 403: // HttpStatusCode.Forbidden
                    throw new AuthorizationFailedException("Authorization failed!");
                case 404: // HttpStatusCode.NotFound
                    throw new NotFoundException("Not found");
                case 409: // HttpStatusCode.Conflict
                    MismatchedDevices mismatchedDevices = null;
                    try
                    {
                        mismatchedDevices = JsonUtil.FromJson<MismatchedDevices>(responseBody);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        Debug.WriteLine(e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new MismatchedDevicesException(mismatchedDevices);
                case 410: // HttpStatusCode.Gone
                    StaleDevices staleDevices = null;
                    try
                    {
                        staleDevices = JsonUtil.FromJson<StaleDevices>(responseBody);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        Debug.WriteLine(e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new StaleDevicesException(staleDevices);
                case 411: //HttpStatusCode.LengthRequired
                    DeviceLimit deviceLimit = null;
                    try
                    {
                        deviceLimit = JsonUtil.FromJson<DeviceLimit>(responseBody);
                    }
                    catch (Exception e)
                    {
                        throw new PushNetworkException(e);
                    }
                    throw new DeviceLimitExceededException(deviceLimit);
                case 417: // HttpStatusCode.ExpectationFailed
                    throw new ExpectationFailedException();
                case 423:
                    RegistrationLockFailure accountLockFailure;
                    try
                    {
                        accountLockFailure = JsonUtil.FromJson<RegistrationLockFailure>(responseBody);
                    }
                    catch (Exception e)
                    {
                        throw new PushNetworkException(e);
                    }
                    throw new LockedException(accountLockFailure.Length, accountLockFailure.TimeRemaining);
            }

            if (responseCode != HttpStatusCode.OK && responseCode != HttpStatusCode.NoContent) // 200 & 204
            {
                throw new NonSuccessfulResponseCodeException("Bad response: " + (int)responseCode + " " +
                                                             responseMessage);
            }

            return responseBody;
        }

#if NETCOREAPP2_1
        private byte[] server_cert_raw;
        private bool ServerCertificateCustomValidationCallback(HttpRequestMessage message, X509Certificate2 cert, X509Chain chain, SslPolicyErrors policy)
        {
            return cert.GetRawCertData().SequenceEqual(server_cert_raw);
        }
#endif

        private async Task<HttpResponseMessage> GetServiceConnectionAsync(CancellationToken token, string urlFragment, string method, string body)
        {
            try
            {
                SignalUrl signalUrl = GetRandom(SignalConnectionInformation.SignalServiceUrls);
                string url = signalUrl.Url;
                string hostHeader = signalUrl.HostHeader;
                Uri uri = new Uri(string.Format("{0}{1}", url, urlFragment));
                Debug.WriteLine("{0}: Uri {1}", TAG, uri);
                HttpClient connection;
#if NETCOREAPP2_1
                HttpClientHandler handler = new HttpClientHandler();
                if (server_cert_raw != null)
                    handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidationCallback;
                connection = new HttpClient(handler);
#else
                connection = new HttpClient();
#endif

                var headers = connection.DefaultRequestHeaders;

                if (CredentialsProvider.Password != null)
                {
                    string authHeader = GetAuthorizationHeader(CredentialsProvider);
                    Debug.WriteLine(String.Format("Authorization: {0}", authHeader), TAG);
                    headers.Add("Authorization", authHeader);
                }

                if (UserAgent != null)
                {
                    headers.Add("X-Signal-Agent", UserAgent);
                }

                if (hostHeader != null)
                {
                    headers.Host = hostHeader;
                }

                StringContent content;
                if (body != null)
                {
                    content = new StringContent(body, Encoding.UTF8, "application/json");
                }
                else
                {
                    content = new StringContent("");
                }
                switch (method)
                {
                    case "POST":
                        return await connection.PostAsync(uri, content, token);

                    case "PUT":
                        return await connection.PutAsync(uri, content, token);

                    case "DELETE":
                        return await connection.DeleteAsync(uri, token);

                    case "GET":
                        return await connection.GetAsync(uri, token);

                    default:
                        throw new Exception("Unknown method: " + method);
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine("getConnection() failed:", TAG);
                Debug.WriteLine(e.Message);
                Debug.WriteLine(e.StackTrace);
                throw new PushNetworkException(e);
            }
        }

        private string GetAuthorizationHeader(CredentialsProvider provider)
        {
            if (provider.DeviceId == SignalServiceAddress.DEFAULT_DEVICE_ID)
            {
                return "Basic " + Base64.EncodeBytes(Encoding.UTF8.GetBytes((provider.User + ":" + provider.Password)));
            }
            else
            {
                return "Basic " + Base64.EncodeBytes(Encoding.UTF8.GetBytes((provider.User + "." + provider.DeviceId + ":" + provider.Password)));
            }
        }

        private SignalUrl GetRandom(SignalUrl[] connections)
        {
            return connections[Util.generateRandomNumber() % connections.Length];
        }
    }

    internal class GcmRegistrationId
    {
        [JsonProperty("wnsRegistrationId")]
        public string WnsRegistrationId { get; }

        [JsonProperty("webSocketChannel")]
        public bool WebSocketChannel { get; }

        public GcmRegistrationId(string wnsRegistrationId, bool webSocketChannel)
        {
            WnsRegistrationId = wnsRegistrationId;
            WebSocketChannel = webSocketChannel;
        }
    }

    internal class RegistrationLock
    {
        [JsonProperty("pin")]
        public string Pin { get; }

        public RegistrationLock(string pin)
        {
            Pin = pin;
        }
    }

    internal class RegistrationLockFailure
    {
        [JsonProperty("length")]
        public int Length { get; private set; }
        [JsonProperty("timeRemaining")]
        public long TimeRemaining { get; private set; }

        public RegistrationLockFailure() { }
    }

    internal class AttachmentDescriptor
    {
        [JsonProperty("id")]
        public ulong Id { get; set; }

        [JsonProperty("location")]
        public string Location { get; set; }

        public AttachmentDescriptor() { }
    }
}
