using Google.Protobuf;
using libsignal;
using libsignal.ecc;
using libsignal.push;
using libsignal.state;
using libsignal.util;
using libsignal_service_dotnet.messages.calls;
using libsignalservice.crypto;
using libsignalservice.messages.multidevice;
using libsignalservice.push;
using libsignalservice.util;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace libsignalservice
{
    /// <summary>
    /// The main interface for creating, registering, and
    /// managing a TextSecure account.
    /// </summary>
    public class SignalServiceAccountManager
    {
        private PushServiceSocket pushServiceSocket;
        private static ProvisioningSocket ProvisioningSocket;
        private SignalServiceUrl[] Urls;
        private readonly string user;
        private readonly string userAgent;

        /// <summary>
        /// Construct a SignalServivceAccountManager.
        /// </summary>
        /// <param name="urls">The URL for the Signal Service.</param>
        /// <param name="user">A Signal Service phone number</param>
        /// <param name="password">A Signal Service password.</param>
        /// <param name="userAgent">A string which identifies the client software.</param>
        public SignalServiceAccountManager(SignalServiceUrl[] urls,
                                        string user, string password, int deviceId, string userAgent)
        {
            this.pushServiceSocket = new PushServiceSocket(urls, new StaticCredentialsProvider(user, password, null, deviceId), userAgent);
            this.user = user;
            this.userAgent = userAgent;
        }

        public SignalServiceAccountManager(SignalServiceUrl[] urls, CancellationToken token, string userAgent)
        {
            Urls = urls;
            ProvisioningSocket = new ProvisioningSocket(urls[0].getUrl(), token);
            pushServiceSocket = new PushServiceSocket(urls, new StaticCredentialsProvider(null, null, null, (int)SignalServiceAddress.DEFAULT_DEVICE_ID), userAgent);
        }

        /// <summary>
        /// Register/Unregister a Google Cloud Messaging registration ID.
        /// </summary>
        /// <param name="gcmRegistrationId">The GCM id to register.  A call with an absent value will unregister.</param>
        /// <returns></returns>
        public void setGcmId(May<string> gcmRegistrationId)// throws IOException
        {
            if (gcmRegistrationId.HasValue)
            {
                this.pushServiceSocket.registerGcmId(gcmRegistrationId.ForceGetValue());
            }
            else
            {
                this.pushServiceSocket.unregisterGcmId();
            }
        }

        /// <summary>
        /// Request an SMS verification code.  On success, the server will send
        /// an SMS verification code to this Signal user.
        /// </summary>
        /// <returns></returns>
        public void requestSmsVerificationCode()// throws IOException
        {
            this.pushServiceSocket.createAccount(false);
        }

        /// <summary>
        /// Request a Voice verification code.  On success, the server will
        /// make a voice call to this Signal user.
        /// </summary>
        /// <returns></returns>
        public void requestVoiceVerificationCode()// throws IOException
        {
            this.pushServiceSocket.createAccount(true);
        }

        /// <summary>
        /// Verify a Signal Service account with a received SMS or voice verification code.
        /// </summary>
        /// <param name="verificationCode">The verification code received via SMS or Voice
        /// <see cref="requestSmsVerificationCode()"/> and <see cref="requestVoiceVerificationCode()"/></param>
        /// <param name="signalingKey">52 random bytes.  A 32 byte AES key and a 20 byte Hmac256 key, concatenated.</param>
        /// <param name="signalProtocolRegistrationId">A random 14-bit number that identifies this Signal install.
        /// This value should remain consistent across registrations for the
        /// same install, but probabilistically differ across registrations
        /// for separate installs.</param>
        /// <param name="voice">A boolean that indicates whether the client supports secure voice (RedPhone) calls. </param>
        /// <returns></returns>
        public void verifyAccountWithCode(string verificationCode, string signalingKey,
                                   uint signalProtocolRegistrationId, bool voice, bool video, bool fetchesMessages)
        {
            this.pushServiceSocket.verifyAccountCode(verificationCode, signalingKey,
                                                 signalProtocolRegistrationId, voice, video, fetchesMessages);
        }

        /// <summary>
        /// Verify a Signal Service account with a signed token from a trusted source.
        /// </summary>
        /// <param name="verificationToken">The signed token provided by a trusted server.</param>
        /// <param name="signalingKey">52 random bytes.  A 32 byte AES key and a 20 byte Hmac256 key, concatenated.</param>
        /// <param name="signalProtocolRegistrationId">A random 14-bit number that identifies this TextSecure install.
        /// This value should remain consistent across registrations for the
        /// same install, but probabilistically differ across registrations
        /// for separate installs.</param>
        /// <param name="voice">A boolean that indicates whether the client supports secure voice (RedPhone) calls.</param>
        /// <returns></returns>
        public void verifyAccountWithToken(string verificationToken, string signalingKey, uint signalProtocolRegistrationId, bool voice, bool video, bool fetchesMessages)
        {
            this.pushServiceSocket.verifyAccountToken(verificationToken, signalingKey, signalProtocolRegistrationId, voice, video, fetchesMessages);
        }

        /// <summary>
        /// Refresh account attributes with server.
        /// </summary>
        /// <param name="signalingKey">52 random bytes.  A 32 byte AES key and a 20 byte Hmac256 key, concatenated.</param>
        /// <param name="signalProtocolRegistrationId">A random 14-bit number that identifies this TextSecure install.
        /// This value should remain consistent across registrations for the same
        /// install, but probabilistically differ across registrations for
        /// separate installs.</param>
        /// <param name="voice">A boolean that indicates whether the client supports secure voice (RedPhone)</param>
        /// <returns></returns>
        public void setAccountAttributes(string signalingKey, uint signalProtocolRegistrationId, bool voice, bool video)
        {
            this.pushServiceSocket.setAccountAttributes(signalingKey, signalProtocolRegistrationId, voice, video, true);
        }

        /// <summary>
        /// Register an identity key, last resort key, signed prekey, and list of one time prekeys
        /// with the server.
        /// </summary>
        /// <param name="identityKey">The client's long-term identity keypair.</param>
        /// <param name="lastResortKey">The client's "last resort" prekey.</param>
        /// <param name="signedPreKey">The client's signed prekey.</param>
        /// <param name="oneTimePreKeys">The client's list of one-time prekeys.</param>
        /// <returns></returns>
        public bool setPreKeys(IdentityKey identityKey, PreKeyRecord lastResortKey,
            SignedPreKeyRecord signedPreKey, IList<PreKeyRecord> oneTimePreKeys)//throws IOException
        {
            this.pushServiceSocket.registerPreKeys(identityKey, lastResortKey, signedPreKey, oneTimePreKeys);
            return true;
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns>The server's count of currently available (eg. unused) prekeys for this user.</returns>
        public int getPreKeysCount()// throws IOException
        {
            return this.pushServiceSocket.getAvailablePreKeys();
        }

        /// <summary>
        /// Set the client's signed prekey.
        /// </summary>
        /// <param name="signedPreKey">The client's new signed prekey.</param>
        public void setSignedPreKey(SignedPreKeyRecord signedPreKey)// throws IOException
        {
            this.pushServiceSocket.setCurrentSignedPreKey(signedPreKey);
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns>The server's view of the client's current signed prekey.</returns>
        public SignedPreKeyEntity getSignedPreKey()// throws IOException
        {
            return this.pushServiceSocket.getCurrentSignedPreKey();
        }

        /// <summary>
        /// Checks whether a contact is currently registered with the server.
        /// </summary>
        /// <param name="e164number">The contact to check.</param>
        /// <returns>An optional ContactTokenDetails, present if registered, absent if not.</returns>
        public May<ContactTokenDetails> getContact(string e164number)// throws IOException
        {
            string contactToken = createDirectoryServerToken(e164number, true);
            ContactTokenDetails contactTokenDetails = this.pushServiceSocket.getContactTokenDetails(contactToken);

            if (contactTokenDetails != null)
            {
                contactTokenDetails.setNumber(e164number);
            }

            return new May<ContactTokenDetails>(contactTokenDetails);
        }

        /// <summary>
        /// Checks which contacts in a set are registered with the server.
        /// </summary>
        /// <param name="e164numbers">The contacts to check.</param>
        /// <returns>A list of ContactTokenDetails for the registered users.</returns>
        public List<ContactTokenDetails> getContacts(IList<string> e164numbers)
        {
            IDictionary<string, string> contactTokensMap = createDirectoryServerTokenMap(e164numbers);
            List<ContactTokenDetails> activeTokens = this.pushServiceSocket.retrieveDirectory(contactTokensMap.Keys);

            foreach (ContactTokenDetails activeToken in activeTokens)
            {
                string number;
                contactTokensMap.TryGetValue(activeToken.getToken(), out number);
                activeToken.setNumber(number);
            }

            return activeTokens;
        }

        public string getAccoountVerificationToken()
        {
            return this.pushServiceSocket.getAccountVerificationToken();
        }

        public string GetNewDeviceUuid(CancellationToken token)
        {
            ProvisioningSocket = new ProvisioningSocket(Urls[0].getUrl(), token);
            return ProvisioningSocket.GetProvisioningUuid().Uuid;
        }

        public string getNewDeviceVerificationCode()// throws IOException
        {
            return this.pushServiceSocket.getNewDeviceVerificationCode();
        }

        public NewDeviceLinkResult FinishNewDeviceRegistration(IdentityKeyPair tempIdentity, string signalingKey, string password, bool sms, bool fetches, int regid, string name)
        {
            ProvisionMessage pm = ProvisioningSocket.GetProvisioningMessage(tempIdentity);
            string provisioningCode = pm.ProvisioningCode;
            byte[] publicKeyBytes = pm.IdentityKeyPublic.ToByteArray();
            if (publicKeyBytes.Length == 32)
            {
                byte[] type = { Curve.DJB_TYPE };
                publicKeyBytes = ByteUtil.combine(type, publicKeyBytes);
            }
            ECPublicKey publicKey = Curve.decodePoint(publicKeyBytes, 0);
            byte[] privateKeyBytes = pm.IdentityKeyPrivate.ToByteArray();
            ECPrivateKey privateKey = Curve.decodePrivatePoint(privateKeyBytes);
            IdentityKeyPair identity = new IdentityKeyPair(new IdentityKey(publicKey), privateKey);
            pushServiceSocket = new PushServiceSocket(Urls, new StaticCredentialsProvider(pm.Number, password, null, -1), userAgent);
            int deviceId = pushServiceSocket.finishNewDeviceRegistration(provisioningCode, signalingKey, sms, fetches, regid, name);
            return new NewDeviceLinkResult()
            {
                DeviceId = deviceId,
                Identity = identity,
                Number = pm.Number
            };
        }

        public void addDevice(string deviceIdentifier,
                              ECPublicKey deviceKey,
                              IdentityKeyPair identityKeyPair,
                              string code)//throws InvalidKeyException, IOException
        {
            ProvisioningCipher cipher = new ProvisioningCipher(deviceKey);
            ProvisionMessage message = new ProvisionMessage
            {
                IdentityKeyPublic = ByteString.CopyFrom(identityKeyPair.getPublicKey().serialize()),
                IdentityKeyPrivate = ByteString.CopyFrom(identityKeyPair.getPrivateKey().serialize()),
                Number = user,
                ProvisioningCode = code
            };

            byte[] ciphertext = cipher.encrypt(message);
            this.pushServiceSocket.sendProvisioningMessage(deviceIdentifier, ciphertext);
        }

        public List<DeviceInfo> getDevices()
        {
            return this.pushServiceSocket.getDevices();
        }

        public void removeDevice(long deviceId)
        {
            this.pushServiceSocket.removeDevice(deviceId);
        }

        public TurnServerInfo getTurnServerInfo()
        {
            return this.pushServiceSocket.getTurnServerInfo();
        }

        public void setSoTimeoutMillis(long soTimeoutMillis)
        {
            this.pushServiceSocket.setSoTimeoutMillis(soTimeoutMillis);
        }

        public void cancelInFlightRequests()
        {
            this.pushServiceSocket.cancelInFlightRequests();
        }

        private string createDirectoryServerToken(string e164number, bool urlSafe)
        {
            try
            {
                byte[] token = Util.trim(Hash.sha1(Encoding.UTF8.GetBytes(e164number)), 10);
                string encoded = Base64.encodeBytesWithoutPadding(token);

                if (urlSafe) return encoded.Replace('+', '-').Replace('/', '_');
                else return encoded;
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        private IDictionary<string, string> createDirectoryServerTokenMap(IList<string> e164numbers)
        {
            IDictionary<string, string> tokenMap = new Dictionary<string, string>(e164numbers.Count);

            foreach (string number in e164numbers)
            {
                var token = createDirectoryServerToken(number, false);
                if (!tokenMap.ContainsKey(token)) // mimic java set behaviour
                {
                    tokenMap.Add(token, number);
                }
            }

            return tokenMap;
        }
    }

    public class NewDeviceLinkResult
    {
        public IdentityKeyPair Identity { get; set; }
        public int DeviceId { get; set; }
        public string Number { get; set; }
    }
}
