using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Google.Protobuf;
using libsignal;
using libsignal.ecc;
using libsignal.push;
using libsignal.state;
using libsignal.util;
using libsignal_service_dotnet.messages.calls;
using libsignalservice.configuration;
using libsignalservice.contacts.crypto;
using libsignalservice.contacts.entities;
using libsignalservice.crypto;
using libsignalservice.messages.multidevice;
using libsignalservice.push;
using libsignalservice.push.http;
using libsignalservice.util;
using libsignalservice.websocket;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Strilanc.Value;

namespace libsignalservice
{
    /// <summary>
    /// The main interface for creating, registering, and
    /// managing a TextSecure account.
    /// </summary>
    public class SignalServiceAccountManager
    {
        private readonly ILogger Logger = LibsignalLogging.CreateLogger<SignalServiceAccountManager>();

        private static ProvisioningSocket? ProvisioningSocket;

        private PushServiceSocket pushServiceSocket;
        private ICredentialsProvider credentials;
        private readonly SignalServiceConfiguration configuration;
        private readonly string userAgent;
        private readonly HttpClient httpClient;

        /// <summary>
        /// Construct a SignalServivceAccountManager
        /// </summary>
        /// <param name="configuration">The URL configuration for the Signal Service</param>
        /// <param name="user">A Signal Service phone number</param>
        /// <param name="password">A Signal Service password</param>
        /// <param name="deviceId">A Signal Service device id</param>
        /// <param name="userAgent">A string which identifies the client software</param>
        public SignalServiceAccountManager(SignalServiceConfiguration configuration,
            string user, string password, int deviceId, string userAgent, HttpClient httpClient) :
            this(configuration, new StaticCredentialsProvider(user, password, deviceId), userAgent, httpClient)
        {
        }

        /// <summary>
        /// Construct a SignalServiceAccountManager for linking as a slave device
        /// </summary>
        /// <param name="configuration">The URL configuration for the Signal Service</param>
        /// <param name="userAgent">A string which identifies the client software</param>
        /// <param name="webSocketFactory">A factory which creates websocket connection objects</param>
        public SignalServiceAccountManager(SignalServiceConfiguration configuration, string userAgent, HttpClient httpClient, ISignalWebSocketFactory webSocketFactory)
        {
            this.httpClient = httpClient;
            this.configuration = configuration;
            this.userAgent = userAgent;
            credentials = new StaticCredentialsProvider(null, null, (int)SignalServiceAddress.DEFAULT_DEVICE_ID);
            pushServiceSocket = new PushServiceSocket(configuration, credentials, userAgent, httpClient);
        }

        public SignalServiceAccountManager(SignalServiceConfiguration configuration,
            ICredentialsProvider credentialsProvider,
            string signalAgent,
            HttpClient httpClient)
        {
            this.pushServiceSocket = new PushServiceSocket(configuration, credentialsProvider, signalAgent, httpClient);
            this.configuration = configuration;
            this.credentials = credentialsProvider;
            this.userAgent = signalAgent;
            this.httpClient = httpClient;
        }

        public async Task<byte[]> GetSenderCertificate(CancellationToken token)
        {
            return await pushServiceSocket.GetSenderCertificate(token);
        }

        /// <summary>
        /// 
        /// </summary>
        public async Task SetPin(CancellationToken token, string pin)
        {
            if (pin != null)
            {
                await pushServiceSocket.SetPin(token, pin);
            }
            else
            {
                await pushServiceSocket.RemovePin(token);
            }
        }

        /// <summary>
        /// Register/Unregister a Google Cloud Messaging registration ID.
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="gcmRegistrationId">The GCM id to register.  A call with an absent value will unregister.</param>
        /// <returns></returns>
        public async Task SetGcmId(CancellationToken token,string gcmRegistrationId)// throws IOException
        {
            if (gcmRegistrationId != null)
            {
                await pushServiceSocket.RegisterGcmId(token, gcmRegistrationId);
            }
            else
            {
                await pushServiceSocket.UnregisterGcmId(token);
            }
        }

        /// <summary>
        /// Request an SMS verification code.  On success, the server will send
        /// an SMS verification code to this Signal user.
        /// </summary>
        /// <returns></returns>
        public async Task RequestSmsVerificationCode(string? captchaToken, CancellationToken? token = null)// throws IOException
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await pushServiceSocket.RequestSmsVerificationCodeAsync(captchaToken, token.Value);
        }

        /// <summary>
        /// Request a Voice verification code.  On success, the server will
        /// make a voice call to this Signal user.
        /// </summary>
        /// <returns></returns>
        public async Task RequestVoiceVerificationCode(string? captchaToken, CancellationToken? token = null)// throws IOException
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await pushServiceSocket.RequestVoiceVerificationCodeAsync(captchaToken, token.Value);
        }

        /// <summary>
        /// Verify a Signal Service account with a received SMS or voice verification code.
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="verificationCode">The verification code received via SMS or Voice
        /// <see cref="RequestSmsVerificationCode(CancellationToken)"/> and <see cref="RequestVoiceVerificationCode(CancellationToken)"/></param>
        /// <param name="signalingKey">52 random bytes.  A 32 byte AES key and a 20 byte Hmac256 key, concatenated.</param>
        /// <param name="signalProtocolRegistrationId">A random 14-bit number that identifies this Signal install.
        /// This value should remain consistent across registrations for the
        /// same install, but probabilistically differ across registrations
        /// for separate installs.</param>
        /// <param name="fetchesMessages">True if the client does not support GCM</param>
        /// <param name="pin"></param>
        /// <param name="unidentifiedAccessKey"></param>
        /// <param name="unrestrictedUnidentifiedAccess"></param>
        /// <returns></returns>
        public async Task VerifyAccountWithCode(CancellationToken token, string verificationCode, string signalingKey,
                                   uint signalProtocolRegistrationId, bool fetchesMessages, string pin,
                                   byte[] unidentifiedAccessKey, bool unrestrictedUnidentifiedAccess)
        {
            await pushServiceSocket.VerifyAccountCode(token, verificationCode, signalingKey,
                                                 signalProtocolRegistrationId, fetchesMessages, pin,
                                                 unidentifiedAccessKey, unrestrictedUnidentifiedAccess);
        }

        /// <summary>
        /// Refresh account attributes with server.
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="signalingKey">52 random bytes.  A 32 byte AES key and a 20 byte Hmac256 key, concatenated.</param>
        /// <param name="signalProtocolRegistrationId">A random 14-bit number that identifies this TextSecure install.
        /// This value should remain consistent across registrations for the same
        /// install, but probabilistically differ across registrations for
        /// separate installs.</param>
        /// <param name="fetchesMessages">True if the client does not support GCM</param>
        /// <param name="pin"></param>
        /// <param name="unidentifiedAccessKey"></param>
        /// <param name="unrestrictedUnidentifiedAccess"></param>
        /// <returns></returns>
        public async Task SetAccountAttributes(CancellationToken token, string signalingKey, uint signalProtocolRegistrationId, bool fetchesMessages, string pin,
            byte[] unidentifiedAccessKey, bool unrestrictedUnidentifiedAccess)
        {
            await pushServiceSocket.SetAccountAttributes(token, signalingKey, signalProtocolRegistrationId, fetchesMessages, pin,
                unidentifiedAccessKey, unrestrictedUnidentifiedAccess);
        }

        /// <summary>
        /// Register an identity key, signed prekey, and list of one time prekeys
        /// with the server.
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="identityKey">The client's long-term identity keypair.</param>
        /// <param name="signedPreKey">The client's signed prekey.</param>
        /// <param name="oneTimePreKeys">The client's list of one-time prekeys.</param>
        /// <returns></returns>
        public async Task<bool> SetPreKeys(CancellationToken token, IdentityKey identityKey, SignedPreKeyRecord signedPreKey, IList<PreKeyRecord> oneTimePreKeys)//throws IOException
        {
            await pushServiceSocket.RegisterPreKeys(token, identityKey, signedPreKey, oneTimePreKeys);
            return true;
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns>The server's count of currently available (eg. unused) prekeys for this user.</returns>
        public async Task<int> GetPreKeysCount(CancellationToken token)// throws IOException
        {
            return await pushServiceSocket.GetAvailablePreKeys(token);
        }

        /// <summary>
        /// Set the client's signed prekey.
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="signedPreKey">The client's new signed prekey.</param>
        public async Task SetSignedPreKey(CancellationToken token, SignedPreKeyRecord signedPreKey)// throws IOException
        {
            await pushServiceSocket.SetCurrentSignedPreKey(token, signedPreKey);
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns>The server's view of the client's current signed prekey.</returns>
        public async Task<SignedPreKeyEntity> GetSignedPreKey(CancellationToken token)// throws IOException
        {
            return await pushServiceSocket.GetCurrentSignedPreKey(token);
        }

        /// <summary>
        /// Checks whether a contact is currently registered with the server
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="e164number">The contact to check.</param>
        /// <returns>An optional ContactTokenDetails, present if registered, absent if not.</returns>
        public async Task<May<ContactTokenDetails>> GetContact(CancellationToken token, string e164number)// throws IOException
        {
            string contactToken = CreateDirectoryServerToken(e164number, true);
            ContactTokenDetails contactTokenDetails = await pushServiceSocket.GetContactTokenDetails(token, contactToken);

            if (contactTokenDetails != null)
            {
                contactTokenDetails.Number = e164number;
            }

            return new May<ContactTokenDetails>(contactTokenDetails);
        }

        /// <summary>
        /// Checks which contacts in a set are registered with the server
        /// </summary>
        /// <param name="token">The cancellation token</param>
        /// <param name="e164numbers">The contacts to check.</param>
        /// <returns>A list of ContactTokenDetails for the registered users.</returns>
        public async Task<List<ContactTokenDetails>> GetContacts(CancellationToken token, IList<string> e164numbers)
        {
            IDictionary<string, string> contactTokensMap = CreateDirectoryServerTokenMap(e164numbers);
            List<ContactTokenDetails> activeTokens = await pushServiceSocket.RetrieveDirectory(token, contactTokensMap.Keys);

            foreach (ContactTokenDetails activeToken in activeTokens)
            {
                contactTokensMap.TryGetValue(activeToken.Token, out string number);
                activeToken.Number = number;
            }

            return activeTokens;
        }

        public async Task<Dictionary<string, Guid>> GetRegisteredUsersAsync(IList<string> e164numbers, string mrenclave, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            try
            {
                string authorization = await pushServiceSocket.GetContactDiscoveryAuthorizationAsync(token);
                Dictionary<string, RemoteAttestation> attestations = await RemoteAttestationUtil.GetAndVerifyMultiRemoteAttestation(pushServiceSocket,
                    PushServiceSocket.ClientSet.ContactDiscovery,
                    mrenclave,
                    mrenclave,
                    authorization);

                List<string> addressBook = new List<string>(e164numbers.Count);

                foreach (string e164number in e164numbers)
                {
                    addressBook.Add(e164number.Substring(1));
                }

                IList<string> cookies = attestations.Values.ToList()[0].Cookies;
                DiscoveryRequest request = ContactDiscoveryCipher.CreateDiscoveryRequest(addressBook, attestations);
                DiscoveryResponse response = await pushServiceSocket.GetContactDiscoveryRegisteredUsersAsync(authorization, request, cookies, mrenclave);
                byte[] data = ContactDiscoveryCipher.GetDiscoveryResponseData(response, attestations.Values);

                Dictionary<string, Guid> results = new Dictionary<string, Guid>(addressBook.Count);
                BinaryReader uuidInputStream = new BinaryReader(new MemoryStream(data));

                foreach (string candidate in addressBook)
                {
                    long candidateUuidHigh = uuidInputStream.ReadInt64();
                    long candidateUuidLow = uuidInputStream.ReadInt64();
                    if (candidateUuidHigh != 0 || candidateUuidLow != 0)
                    {
                        results.Add($"+{candidate}", Util.JavaUUIDToCSharpGuid(candidateUuidHigh, candidateUuidLow));
                    }
                }

                return results;
            }
            catch (InvalidCipherTextException ex)
            {
                throw new UnauthenticatedResponseException(ex);
            }
        }

        /// <summary>
        /// Request a UUID from the server for linking as a new device.
        /// Called by the new device.
        /// </summary>
        /// <param name="token">A CancellationToken for the PrivisioningSocket's websocket connection</param>
        /// /// <param name="webSocketFactory">A factory which creates websocket connection objects</param>
        /// <returns></returns>
        public async Task<string> GetNewDeviceUuid(CancellationToken token, ISignalWebSocketFactory webSocketFactory)
        {
            ProvisioningSocket = new ProvisioningSocket(configuration.SignalServiceUrls[0].Url, webSocketFactory, token);
            return (await ProvisioningSocket.GetProvisioningUuid(token)).Uuid;
        }

        /// <summary>
        /// Request a code for verification of a new device.
        /// Called by an already verified device.
        /// </summary>
        /// <returns>A verification code (String of 6 digits)</returns>
        public async Task<string> GetNewDeviceVerificationCode(CancellationToken token)// throws IOException
        {
            return await pushServiceSocket.GetNewDeviceVerificationCode(token);
        }

        /// <summary>
        /// Fetch a ProvisionMessage from the server.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="tempIdentity"></param>
        /// <returns></returns>
        public async Task<SignalServiceProvisionMessage> GetProvisioningMessage(CancellationToken token, IdentityKeyPair tempIdentity)
        {
            if (ProvisioningSocket == null)
            {
                throw new NullReferenceException($"{nameof(ProvisioningSocket)} is null. Maybe you forgot to call GetNewDeviceUuid?");
            }
            ProvisionMessage protoPm = await ProvisioningSocket.GetProvisioningMessage(token, tempIdentity);
            string provisioningCode = protoPm.ProvisioningCode;
            byte[] publicKeyBytes = protoPm.IdentityKeyPublic.ToByteArray();
            if (publicKeyBytes.Length == 32)
            {
                byte[] type = { Curve.DJB_TYPE };
                publicKeyBytes = ByteUtil.combine(type, publicKeyBytes);
            }
            ECPublicKey publicKey = Curve.decodePoint(publicKeyBytes, 0);
            byte[] privateKeyBytes = protoPm.IdentityKeyPrivate.ToByteArray();
            ECPrivateKey privateKey = Curve.decodePrivatePoint(privateKeyBytes);
            IdentityKeyPair identity = new IdentityKeyPair(new IdentityKey(publicKey), privateKey);
            return new SignalServiceProvisionMessage()
            {
                Number = protoPm.Number,
                Identity = identity,
                Code = protoPm.ProvisioningCode
            };
        }

        /// <summary>
        /// Finishes a registration as a new device.
        /// Called by the new device. This method blocks until the already verified device has verified this device.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="provisionMessage"></param>
        /// <param name="signalingKey"></param>
        /// <param name="password"></param>
        /// <param name="sms"></param>
        /// <param name="fetches"></param>
        /// <param name="regid"></param>
        /// <param name="name"></param>
        /// <returns>Device id</returns>
        public async Task<int> FinishNewDeviceRegistration(CancellationToken token, SignalServiceProvisionMessage provisionMessage, string signalingKey, string password, bool sms, bool fetches, int regid, string name)
        {
            pushServiceSocket = new PushServiceSocket(configuration, new StaticCredentialsProvider(provisionMessage.Number, password, -1), userAgent, httpClient);

            // update credentials and pushServiceSocket to keep internal state consistent
            int deviceId = await pushServiceSocket.FinishNewDeviceRegistration(token, provisionMessage.Code, signalingKey, sms, fetches, regid, name);
            credentials = new StaticCredentialsProvider(provisionMessage.Number, password, deviceId);
            pushServiceSocket = new PushServiceSocket(configuration, credentials, userAgent, httpClient);
            return deviceId;
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="token"></param>
        /// <param name="deviceIdentifier"></param>
        /// <param name="deviceKey"></param>
        /// <param name="identityKeyPair"></param>
        /// <param name="profileKey"></param>
        /// <param name="code"></param>
        public async Task AddDevice(CancellationToken token,
            string deviceIdentifier,
            ECPublicKey deviceKey,
            IdentityKeyPair identityKeyPair,
            byte[] profileKey,
            string code)//throws InvalidKeyException, IOException
        {
            ProvisioningCipher cipher = new ProvisioningCipher(deviceKey);
            ProvisionMessage message = new ProvisionMessage
            {
                IdentityKeyPublic = ByteString.CopyFrom(identityKeyPair.getPublicKey().serialize()),
                IdentityKeyPrivate = ByteString.CopyFrom(identityKeyPair.getPrivateKey().serialize()),
                Number = credentials.User,
                ProvisioningCode = code
            };

            if (profileKey != null)
            {
                message.ProfileKey = ByteString.CopyFrom(profileKey);
            }

            byte[] ciphertext = cipher.encrypt(message);
            await pushServiceSocket.SendProvisioningMessage(token, deviceIdentifier, ciphertext);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <returns></returns>
        public async Task<List<DeviceInfo>> GetDevices(CancellationToken token)
        {
            return await pushServiceSocket.GetDevices(token);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="token"></param>
        /// <param name="deviceId"></param>
        public async Task RemoveDevice(CancellationToken token, long deviceId)
        {
            await pushServiceSocket.RemoveDevice(token, deviceId);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <returns></returns>
        public async Task<TurnServerInfo> GetTurnServerInfo(CancellationToken token)
        {
            return await this.pushServiceSocket.GetTurnServerInfo(token);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="key"></param>
        /// <param name="name"></param>
        /// <param name="token"></param>
        public async Task SetProfileName(CancellationToken token, byte[] key, string name)
        {
            if (name == null) name = "";
            string ciphertextName = Base64.EncodeBytesWithoutPadding(new ProfileCipher(key).EncryptName(Encoding.Unicode.GetBytes(name), ProfileCipher.NAME_PADDED_LENGTH));
            await pushServiceSocket.SetProfileName(token, ciphertextName);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="token"></param>
        /// <param name="key"></param>
        /// <param name="avatar"></param>
        public async Task SetProfileAvatar(CancellationToken token, byte[] key, StreamDetails avatar)
        {
            ProfileAvatarData profileAvatarData = null;
            if (avatar != null)
            {
                profileAvatarData = new ProfileAvatarData(avatar.InputStream, avatar.Length, avatar.ContentType, new ProfileCipherOutputStreamFactory(key));
            }
            await pushServiceSocket.SetProfileAvatar(token, profileAvatarData);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="soTimeoutMillis"></param>
        public void SetSoTimeoutMillis(long soTimeoutMillis)
        {
            this.pushServiceSocket.SetSoTimeoutMillis(soTimeoutMillis);
        }

        /// <summary>
        /// TODO
        /// </summary>
        public void CancelInFlightRequests()
        {
            this.pushServiceSocket.CancelInFlightRequests();
        }

        private string CreateDirectoryServerToken(string e164number, bool urlSafe)
        {
            try
            {
                byte[] token = Util.Trim(Hash.Sha1(Encoding.UTF8.GetBytes(e164number)), 10);
                string encoded = Base64.EncodeBytesWithoutPadding(token);

                if (urlSafe) return encoded.Replace('+', '-').Replace('/', '_');
                else return encoded;
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        private IDictionary<string, string> CreateDirectoryServerTokenMap(IList<string> e164numbers)
        {
            IDictionary<string, string> tokenMap = new Dictionary<string, string>(e164numbers.Count);

            foreach (string number in e164numbers)
            {
                var token = CreateDirectoryServerToken(number, false);
                if (!tokenMap.ContainsKey(token)) // mimic Java set behavior
                {
                    tokenMap.Add(token, number);
                }
            }

            return tokenMap;
        }
    }

    public class SignalServiceProvisionMessage
    {
        public IdentityKeyPair? Identity { get; internal set; }
        public string? Number { get; internal set; }
        public string? Code { get; internal set; }
    }
}
