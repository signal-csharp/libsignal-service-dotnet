using libsignal;
using libsignal.ecc;
using libsignal.push;
using libsignal.state;
using libsignal_service_dotnet.messages.calls;
using libsignalservice.messages.multidevice;
using libsignalservice.push.exceptions;
using libsignalservice.util;
using Newtonsoft.Json;
using Strilanc.Value;

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
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace libsignalservice.push
{
    public class PushServiceSocket
    {
        private static readonly string TAG = "PushServiceSocket";

        private static readonly string CREATE_ACCOUNT_SMS_PATH = "/v1/accounts/sms/code/{0}";
        private static readonly string CREATE_ACCOUNT_VOICE_PATH = "/v1/accounts/voice/code/{0}";
        private static readonly string VERIFY_ACCOUNT_CODE_PATH = "/v1/accounts/code/{0}";
        private static readonly string VERIFY_ACCOUNT_TOKEN_PATH = "/v1/accounts/token/{0}";
        private static readonly string REGISTER_GCM_PATH = "/v1/accounts/gcm/";
        private static readonly string REQUEST_TOKEN_PATH = "/v1/accounts/token";
        private static readonly string TURN_SERVER_INFO = "/v1/accounts/turn";
        private static readonly string SET_ACCOUNT_ATTRIBUTES = "/v1/accounts/attributes";

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
        private static readonly string RECEIPT_PATH = "/v1/receipt/{0}/{1}";
        private static readonly string ATTACHMENT_PATH = "/v1/attachments/{0}";

        private static readonly string PROFILE_PATH = "/v1/profile/%s";

        private readonly SignalConnectionInformation[] signalConnectionInformation;
        private readonly CredentialsProvider credentialsProvider;
        private readonly string userAgent;

        public PushServiceSocket(SignalServiceUrl[] serviceUrls, CredentialsProvider credentialsProvider, string userAgent)
        {
            this.credentialsProvider = credentialsProvider;
            this.userAgent = userAgent;
            this.signalConnectionInformation = new SignalConnectionInformation[serviceUrls.Length];

            for (int i = 0; i < serviceUrls.Length; i++)
            {
                signalConnectionInformation[i] = new SignalConnectionInformation(serviceUrls[i]);
            }
        }

        public bool createAccount(bool voice) //throws IOException
        {
            string path = voice ? CREATE_ACCOUNT_VOICE_PATH : CREATE_ACCOUNT_SMS_PATH;
            makeRequest(string.Format(path, credentialsProvider.GetUser()), "GET", null);
            return true;
        }

        public bool verifyAccountCode(string verificationCode, string signalingKey, uint registrationId, bool fetchesMessages)
        {
            AccountAttributes signalingKeyEntity = new AccountAttributes(signalingKey, registrationId, fetchesMessages);
            makeRequest(string.Format(VERIFY_ACCOUNT_CODE_PATH, verificationCode), "PUT", JsonUtil.toJson(signalingKeyEntity));
            return true;
        }

        public bool setAccountAttributes(string signalingKey, uint registrationId, bool fetchesMessages)
        {
            AccountAttributes accountAttributesEntity = new AccountAttributes(signalingKey, registrationId, fetchesMessages);
            makeRequest(SET_ACCOUNT_ATTRIBUTES, "PUT", JsonUtil.toJson(accountAttributesEntity));
            return true;
        }

        public string getAccountVerificationToken()// throws IOException
        {
            string responseText = makeRequest(REQUEST_TOKEN_PATH, "GET", null);
            return JsonUtil.fromJson<AuthorizationToken>(responseText).Token;
        }

        public int finishNewDeviceRegistration(String code, String signalingKey, bool supportsSms, bool fetchesMessages, int registrationId, String deviceName)
        {
            ConfirmCodeMessage javaJson = new ConfirmCodeMessage(signalingKey, supportsSms, fetchesMessages, registrationId, deviceName);
            string json = JsonUtil.toJson(javaJson);
            string responseText = makeRequest(string.Format(DEVICE_PATH, code), "PUT", json);
            DeviceId response = JsonUtil.fromJson<DeviceId>(responseText);
            return response.deviceId;
        }

        public string getNewDeviceVerificationCode()// throws IOException
        {
            string responseText = makeRequest(PROVISIONING_CODE_PATH, "GET", null);
            return JsonUtil.fromJson<DeviceCode>(responseText).getVerificationCode();
        }

        public bool sendProvisioningMessage(string destination, byte[] body)// throws IOException
        {
            makeRequest(string.Format(PROVISIONING_MESSAGE_PATH, destination), "PUT",
                    JsonUtil.toJson(new ProvisioningMessage(Base64.encodeBytes(body))));
            return true;
        }

        public List<DeviceInfo> getDevices()// throws IOException
        {
            string responseText = makeRequest(string.Format(DEVICE_PATH, ""), "GET", null);
            return JsonUtil.fromJson<DeviceInfoList>(responseText).getDevices();
        }

        public bool removeDevice(long deviceId)// throws IOException
        {
            makeRequest(string.Format(DEVICE_PATH, deviceId), "DELETE", null);
            return true;
        }

        public bool sendReceipt(string destination, ulong messageId, May<string> relay)// throws IOException
        {
            string path = string.Format(RECEIPT_PATH, destination, messageId);

            if (relay.HasValue)
            {
                path += "?relay=" + relay.ForceGetValue();
            }

            makeRequest(path, "PUT", null);
            return true;
        }

        public void registerGcmId(String gcmRegistrationId)
        {
            GcmRegistrationId registration = new GcmRegistrationId(gcmRegistrationId, true);
            makeRequest(REGISTER_GCM_PATH, "PUT", JsonUtil.toJson(registration));
        }

        public void unregisterGcmId()
        {
            makeRequest(REGISTER_GCM_PATH, "DELETE", null);
        }

        public SendMessageResponse sendMessage(OutgoingPushMessageList bundle)
        {
            try
            {
                string responseText = makeRequest(string.Format(MESSAGE_PATH, bundle.getDestination()), "PUT", JsonUtil.toJson(bundle));
                return JsonUtil.fromJson<SendMessageResponse>(responseText);
            }
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(bundle.getDestination(), nfe);
            }
        }

        public List<SignalServiceEnvelopeEntity> getMessages()// throws IOException
        {
            string responseText = makeRequest(string.Format(MESSAGE_PATH, ""), "GET", null);
            return JsonUtil.fromJson<SignalServiceEnvelopeEntityList>(responseText).getMessages();
        }

        public bool acknowledgeMessage(string sender, ulong timestamp)// throws IOException
        {
            makeRequest(string.Format(ACKNOWLEDGE_MESSAGE_PATH, sender, timestamp), "DELETE", null);
            return true;
        }

        public bool registerPreKeys(IdentityKey identityKey,
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

            makeRequest(string.Format(PREKEY_PATH, ""), "PUT",
                JsonUtil.toJson(new PreKeyState(entities, signedPreKeyEntity, identityKey)));
            return true;
        }

        public int getAvailablePreKeys()// throws IOException
        {
            string responseText = makeRequest(PREKEY_METADATA_PATH, "GET", null);
            PreKeyStatus preKeyStatus = JsonUtil.fromJson<PreKeyStatus>(responseText);

            return preKeyStatus.getCount();
        }

        public List<PreKeyBundle> getPreKeys(SignalServiceAddress destination, uint deviceIdInteger)// throws IOException
        {
            try
            {
                string deviceId = deviceIdInteger.ToString();

                if (deviceId.Equals("1"))
                    deviceId = "*";

                string path = string.Format(PREKEY_DEVICE_PATH, destination.getNumber(), deviceId);

                if (destination.getRelay().HasValue)
                {
                    path = path + "?relay=" + destination.getRelay().ForceGetValue();
                }

                string responseText = makeRequest(path, "GET", null);
                PreKeyResponse response = JsonUtil.fromJson<PreKeyResponse>(responseText);
                List<PreKeyBundle> bundles = new List<PreKeyBundle>();

                foreach (PreKeyResponseItem device in response.getDevices())
                {
                    ECPublicKey preKey = null;
                    ECPublicKey signedPreKey = null;
                    byte[] signedPreKeySignature = null;
                    int preKeyId = -1;
                    int signedPreKeyId = -1;

                    if (device.getSignedPreKey() != null)
                    {
                        signedPreKey = device.getSignedPreKey().getPublicKey();
                        signedPreKeyId = (int)device.getSignedPreKey().getKeyId(); // TODO: whacky
                        signedPreKeySignature = device.getSignedPreKey().getSignature();
                    }

                    if (device.getPreKey() != null)
                    {
                        preKeyId = (int)device.getPreKey().getKeyId();// TODO: whacky
                        preKey = device.getPreKey().getPublicKey();
                    }

                    bundles.Add(new PreKeyBundle(device.getRegistrationId(), device.getDeviceId(), (uint)preKeyId,
                                                         preKey, (uint)signedPreKeyId, signedPreKey, signedPreKeySignature,
                                                         response.getIdentityKey()));// TODO: whacky
                }

                return bundles;
            }
            /*catch (JsonUtil.JsonParseException e)
            {
                throw new IOException(e);
            }*/
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(destination.getNumber(), nfe);
            }
        }

        public PreKeyBundle getPreKey(SignalServiceAddress destination, uint deviceId)// throws IOException
        {
            try
            {
                string path = string.Format(PREKEY_DEVICE_PATH, destination.getNumber(),
                                            deviceId.ToString());

                if (destination.getRelay().HasValue)
                {
                    path = path + "?relay=" + destination.getRelay().ForceGetValue();
                }

                string responseText = makeRequest(path, "GET", null);
                PreKeyResponse response = JsonUtil.fromJson<PreKeyResponse>(responseText);

                if (response.getDevices() == null || response.getDevices().Count < 1)
                    throw new Exception("Empty prekey list");

                PreKeyResponseItem device = response.getDevices()[0];
                ECPublicKey preKey = null;
                ECPublicKey signedPreKey = null;
                byte[] signedPreKeySignature = null;
                int preKeyId = -1;
                int signedPreKeyId = -1;

                if (device.getPreKey() != null)
                {
                    preKeyId = (int)device.getPreKey().getKeyId();// TODO: whacky
                    preKey = device.getPreKey().getPublicKey();
                }

                if (device.getSignedPreKey() != null)
                {
                    signedPreKeyId = (int)device.getSignedPreKey().getKeyId();// TODO: whacky
                    signedPreKey = device.getSignedPreKey().getPublicKey();
                    signedPreKeySignature = device.getSignedPreKey().getSignature();
                }

                return new PreKeyBundle(device.getRegistrationId(), device.getDeviceId(), (uint)preKeyId, preKey,
                                        (uint)signedPreKeyId, signedPreKey, signedPreKeySignature, response.getIdentityKey());
            }
            /*catch (JsonUtil.JsonParseException e)
            {
                throw new IOException(e);
            }*/
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(destination.getNumber(), nfe);
            }
        }

        public SignedPreKeyEntity getCurrentSignedPreKey()// throws IOException
        {
            try
            {
                string responseText = makeRequest(SIGNED_PREKEY_PATH, "GET", null);
                return JsonUtil.fromJson<SignedPreKeyEntity>(responseText);
            }
            catch (/*NotFound*/Exception e)
            {
                Debug.WriteLine(e.Message, TAG);
                return null;
            }
        }

        public bool setCurrentSignedPreKey(SignedPreKeyRecord signedPreKey)// throws IOException
        {
            SignedPreKeyEntity signedPreKeyEntity = new SignedPreKeyEntity(signedPreKey.getId(),
                                                                           signedPreKey.getKeyPair().getPublicKey(),
                                                                           signedPreKey.getSignature());
            makeRequest(SIGNED_PREKEY_PATH, "PUT", JsonUtil.toJson(signedPreKeyEntity));
            return true;
        }

        public Tuple<ulong, byte[]> SendAttachment(PushAttachmentData attachment)// throws IOException
        {
            string response = makeRequest(string.Format(ATTACHMENT_PATH, ""), "GET", null);
            AttachmentDescriptor attachmentKey = JsonUtil.fromJson<AttachmentDescriptor>(response);

            if (attachmentKey == null || attachmentKey.getLocation() == null)
            {
                throw new Exception("Server failed to allocate an attachment key!");
            }

            Debug.WriteLine("Got attachment content location: " + attachmentKey.getLocation(), TAG);

            byte[] digest = UploadAttachment("PUT", attachmentKey.getLocation(), attachment.getData(),
                attachment.getDataSize(), attachment.getKey());

            return new Tuple<ulong, byte[]>(attachmentKey.getId(), digest);
        }

        public void retrieveAttachment(string relay, ulong attachmentId, Stream tmpDestination, int maxSizeBytes)
        {
            string attachmentUrlLocation = RetrieveAttachmentUrl(relay, attachmentId);
            downloadExternalFile(attachmentUrlLocation, tmpDestination);
        }

        /// <summary>
        /// Gets the URL location of an attachment
        /// </summary>
        /// <param name="relay"></param>
        /// <param name="attachmentId"></param>
        /// <returns></returns>
        public string RetrieveAttachmentUrl(string relay, ulong attachmentId)
        {
            string path = string.Format(ATTACHMENT_PATH, attachmentId.ToString());

            if (!Util.isEmpty(relay))
            {
                path = path + "?relay=" + relay;
            }

            string response = makeRequest(path, "GET", null);
            Debug.WriteLine("PushServiceSocket: Received resp " + response);
            AttachmentDescriptor descriptor = JsonUtil.fromJson<AttachmentDescriptor>(response);
            Debug.WriteLine("PushServiceSocket: Attachment: " + attachmentId + " is at: " + descriptor.getLocation());
            return descriptor.getLocation();
        }

        public SignalServiceProfile RetrieveProfile(SignalServiceAddress target)
        {
            try
            {
                string response = makeRequest(string.Format(PROFILE_PATH, target.getNumber()), "GET", null);
                return JsonUtil.fromJson<SignalServiceProfile>(response);
            }
            catch (Exception e)
            {
                throw new NonSuccessfulResponseCodeException("Unable to parse entity: "+e.Message);
            }
        }

        public List<ContactTokenDetails> retrieveDirectory(ICollection<string> contactTokens) // TODO: whacky
                                                                                              //throws NonSuccessfulResponseCodeException, PushNetworkException
        {
            LinkedList<HashSet<string>> temp = new LinkedList<HashSet<string>>();
            ContactTokenList contactTokenList = new ContactTokenList(contactTokens.ToList());
            string response = makeRequest(DIRECTORY_TOKENS_PATH, "PUT", JsonUtil.toJson(contactTokenList));
            ContactTokenDetailsList activeTokens = JsonUtil.fromJson<ContactTokenDetailsList>(response);

            return activeTokens.getContacts();
        }

        public ContactTokenDetails getContactTokenDetails(string contactToken)// throws IOException
        {
            try
            {
                string response = makeRequest(string.Format(DIRECTORY_VERIFY_PATH, contactToken), "GET", null);
                return JsonUtil.fromJson<ContactTokenDetails>(response);
            }
            catch (/*NotFound*/Exception nfe)
            {
                return null;
            }
        }

        public TurnServerInfo getTurnServerInfo()
        {
            throw new NotImplementedException();
        }

        public void setSoTimeoutMillis(long soTimeoutMillis)
        {
            throw new NotImplementedException();
        }

        public void cancelInFlightRequests()
        {
            throw new NotImplementedException();
        }

        private void downloadExternalFile(string url, Stream localDestination)
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


        private byte[] UploadAttachment(string method, string url, Stream data, ulong dataSize, byte[] key) //throws IOException
        {
            StreamContent streamContent = new StreamContent(data);
            var request = new HttpRequestMessage(HttpMethod.Put, url);
            request.Content = streamContent;
            request.Properties.Add("Content-Type", "application/octet-stream");
            request.Properties.Add("Connection", "close");

            //TODO encrypt
            throw new NotImplementedException();

            var client = new HttpClient();
            HttpResponseMessage response = client.SendAsync(request).Result;

            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new IOException("bad response: " + response.StatusCode);
            }
            return response.Content.ReadAsByteArrayAsync().Result;
        }

        private string makeRequest(string urlFragment, string method, string body)
        //throws NonSuccessfulResponseCodeException, PushNetworkException
        {
            HttpResponseMessage connection = getConnection(urlFragment, method, body);
            HttpStatusCode responseCode;
            string responseMessage;
            string responseBody;

            try
            {
                responseCode = connection.StatusCode;
                responseMessage = connection.ReasonPhrase;
                responseBody = connection.Content.ReadAsStringAsync().Result;
            }
            catch (Exception ioe)
            {
                Debug.WriteLine(ioe.Message);
                Debug.WriteLine(ioe.StackTrace);
                throw new PushNetworkException(ioe);
            }

            switch (responseCode)
            {
                case HttpStatusCode.RequestEntityTooLarge: // 413
                    throw new RateLimitException("Rate limit exceeded: " + responseCode);
                case HttpStatusCode.Unauthorized: // 401
                case HttpStatusCode.Forbidden: // 403
                    throw new AuthorizationFailedException("Authorization failed!");
                case HttpStatusCode.NotFound: // 404
                    throw new NotFoundException("Not found");
                case HttpStatusCode.Conflict: // 409
                    MismatchedDevices mismatchedDevices = null;
                    try
                    {
                        mismatchedDevices = JsonUtil.fromJson<MismatchedDevices>(responseBody);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        Debug.WriteLine(e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new MismatchedDevicesException(mismatchedDevices);
                case HttpStatusCode.Gone: // 410
                    StaleDevices staleDevices = null;
                    try
                    {
                        staleDevices = JsonUtil.fromJson<StaleDevices>(responseBody);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        Debug.WriteLine(e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new StaleDevicesException(staleDevices);
                case HttpStatusCode.LengthRequired://411:
                    DeviceLimit deviceLimit = null;
                    try
                    {
                        deviceLimit = JsonUtil.fromJson<DeviceLimit>(responseBody);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        Debug.WriteLine(e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new DeviceLimitExceededException(deviceLimit);
                case HttpStatusCode.ExpectationFailed: // 417
                    throw new ExpectationFailedException();
            }

            if (responseCode != HttpStatusCode.OK && responseCode != HttpStatusCode.NoContent) // 200 & 204
            {
                throw new NonSuccessfulResponseCodeException("Bad response: " + (int)responseCode + " " +
                                                             responseMessage);
            }

            return responseBody;
        }

        private bool Func(HttpRequestMessage a, X509Certificate2 b, X509Chain c, SslPolicyErrors d)
        {
            return true;
        }

        private HttpResponseMessage getConnection(string urlFragment, string method, string body)
        {
            try
            {
                SignalConnectionInformation connectionInformation = getRandom(signalConnectionInformation);
                string url = connectionInformation.getUrl();
                May<string> hostHeader = connectionInformation.getHostHeader();
                Uri uri = new Uri(string.Format("{0}{1}", url, urlFragment));
                Debug.WriteLine("{0}: Uri {1}", TAG, uri);
                HttpClient connection = new HttpClient();

                var headers = connection.DefaultRequestHeaders;

                if (credentialsProvider.GetPassword() != null)
                {
                    string authHeader = getAuthorizationHeader();
                    Debug.WriteLine(String.Format("Authorization: {0}", authHeader), TAG);
                    headers.Add("Authorization", authHeader);
                }

                if (userAgent != null)
                {
                    headers.Add("X-Signal-Agent", userAgent);
                }

                if (hostHeader.HasValue)
                {
                    headers.Host = hostHeader.ForceGetValue();
                }

                StringContent content;
                if (body != null)
                {
                    content = new StringContent(body, Encoding.UTF8, "application/json");
                    Debug.WriteLine(body);
                }
                else
                {
                    content = new StringContent("");
                }
                switch (method)
                {
                    case "POST":
                        return connection.PostAsync(uri, content).Result;

                    case "PUT":
                        return connection.PutAsync(uri, content).Result;

                    case "DELETE":
                        return connection.DeleteAsync(uri).Result;

                    case "GET":
                        return connection.GetAsync(uri).Result;

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

        private string getAuthorizationHeader()
        {
            if (credentialsProvider.GetDeviceId() == SignalServiceAddress.DEFAULT_DEVICE_ID)
            {
                return "Basic " + Base64.encodeBytes(Encoding.UTF8.GetBytes((credentialsProvider.GetUser() + ":" + credentialsProvider.GetPassword())));
            }
            else
            {
                return "Basic " + Base64.encodeBytes(Encoding.UTF8.GetBytes((credentialsProvider.GetUser() + "." + credentialsProvider.GetDeviceId() + ":" + credentialsProvider.GetPassword())));
            }
        }

        private SignalConnectionInformation getRandom(SignalConnectionInformation[] connections)
        {
            return connections[Util.generateRandomNumber() % connections.Length];
        }
    }

    internal class GcmRegistrationId
    {
        [JsonProperty]
        private string wnsRegistrationId;

        [JsonProperty]
        private bool webSocketChannel;

        public GcmRegistrationId()
        {
        }

        public GcmRegistrationId(string wnsRegistrationId, bool webSocketChannel)
        {
            this.wnsRegistrationId = wnsRegistrationId;
            this.webSocketChannel = webSocketChannel;
        }
    }

    internal class AttachmentDescriptor
    {
        [JsonProperty]
        private ulong id;

        [JsonProperty]
        private string location;

        public ulong getId()
        {
            return id;
        }

        public string getLocation()
        {
            return location;
        }
    }

    internal class SignalConnectionInformation
    {
        private readonly string url;
        private readonly May<string> hostHeader;
        //private readonly TrustManager[] trustManagers;

        public SignalConnectionInformation(SignalServiceUrl signalServiceUrl)
        {
            this.url = signalServiceUrl.getUrl();
            this.hostHeader = signalServiceUrl.getHostHeader();
            //this.trustManagers = BlacklistingTrustManager.createFor(signalServiceUrl.getTrustStore());
        }

        public string getUrl()
        {
            return url;
        }

        public May<string> getHostHeader()
        {
            return hostHeader;
        }

        //TrustManager[] getTrustManagers()
        //{
        //    return trustManagers;
        //}

        //public May<ConnectionSpec> getConnectionSpec()
        //{
        //    return connectionSpec;
        //}
    }
}
