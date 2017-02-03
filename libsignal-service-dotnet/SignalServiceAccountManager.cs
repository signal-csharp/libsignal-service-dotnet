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
using System.Text;
using System.Threading.Tasks;
using libsignal;
using libsignal.ecc;
using libsignal.state;
using libsignalservice.crypto;
using libsignalservice.messages.multidevice;
using libsignalservice.push;
using libsignalservice.util;
using Strilanc.Value;
using Google.Protobuf;

namespace libsignalservice
{
    /// <summary>
    /// The main interface for creating, registering, and
    /// managing a TextSecure account.
    /// </summary>
    public class SignalServiceAccountManager
    {

        private readonly PushServiceSocket pushServiceSocket;
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
                                        string user, string password, string userAgent)
        {
            this.pushServiceSocket = new PushServiceSocket(urls, new StaticCredentialsProvider(user, password, null), userAgent);
            this.user = user;
            this.userAgent = userAgent;
        }

        /// <summary>
        /// Register/Unregister a Google Cloud Messaging registration ID.
        /// </summary>
        /// <param name="wnsRegistrationId">The GCM id to register.  A call with an absent value will unregister.</param>
        /// <returns></returns>
        public async Task<bool> setWnsId(May<string> wnsRegistrationId)// throws IOException
        {
            if (wnsRegistrationId.HasValue)
            {
                return await this.pushServiceSocket.registerWnsId(wnsRegistrationId.ForceGetValue());
            }
            else
            {
                return await this.pushServiceSocket.unregisterWnsId();
            }
        }

        /// <summary>
        /// Request an SMS verification code.  On success, the server will send
        /// an SMS verification code to this Signal user.
        /// </summary>
        /// <returns></returns>
        public void requestSmsVerificationCode()// throws IOException
        {
            this.pushServiceSocket.createAccount(false).Wait();
        }

        /// <summary>
        /// Request a Voice verification code.  On success, the server will
        /// make a voice call to this Signal user.
        /// </summary>
        /// <returns></returns>
        public void requestVoiceVerificationCode()// throws IOException
        {
            this.pushServiceSocket.createAccount(true).Wait();
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
        public async Task verifyAccountWithCode(string verificationCode, string signalingKey,
                                   uint signalProtocolRegistrationId, bool voice)
        {
            await this.pushServiceSocket.verifyAccountCode(verificationCode, signalingKey,
                                                 signalProtocolRegistrationId, voice);
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
        public async Task verifyAccountWithToken(string verificationToken, string signalingKey, uint signalProtocolRegistrationId, bool voice)
        {
            await this.pushServiceSocket.verifyAccountToken(verificationToken, signalingKey, signalProtocolRegistrationId, voice);
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
        public async Task setAccountAttributes(string signalingKey, uint signalProtocolRegistrationId, bool voice)
        {
            await this.pushServiceSocket.setAccountAttributes(signalingKey, signalProtocolRegistrationId, voice, true);
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
        public async Task<bool> setPreKeys(IdentityKey identityKey, PreKeyRecord lastResortKey,
            SignedPreKeyRecord signedPreKey, IList<PreKeyRecord> oneTimePreKeys)//throws IOException
        {
            await this.pushServiceSocket.registerPreKeys(identityKey, lastResortKey, signedPreKey, oneTimePreKeys);
            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>The server's count of currently available (eg. unused) prekeys for this user.</returns>
        public async Task<int> getPreKeysCount()// throws IOException
        {
            return await this.pushServiceSocket.getAvailablePreKeys();
        }

        /// <summary>
        /// Set the client's signed prekey.
        /// </summary>
        /// <param name="signedPreKey">The client's new signed prekey.</param>
        public async void setSignedPreKey(SignedPreKeyRecord signedPreKey)// throws IOException
        {
            await this.pushServiceSocket.setCurrentSignedPreKey(signedPreKey);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>The server's view of the client's current signed prekey.</returns>
        public async Task<SignedPreKeyEntity> getSignedPreKey()// throws IOException
        {
            return await this.pushServiceSocket.getCurrentSignedPreKey();
        }

        /// <summary>
        /// Checks whether a contact is currently registered with the server.
        /// </summary>
        /// <param name="e164number">The contact to check.</param>
        /// <returns>An optional ContactTokenDetails, present if registered, absent if not.</returns>
        public async Task<May<ContactTokenDetails>> getContact(string e164number)// throws IOException
        {
            string contactToken = createDirectoryServerToken(e164number, true);
            ContactTokenDetails contactTokenDetails = await this.pushServiceSocket.getContactTokenDetails(contactToken);

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
        public async Task<List<ContactTokenDetails>> getContacts(IList<string> e164numbers)
        {
            IDictionary<string, string> contactTokensMap = createDirectoryServerTokenMap(e164numbers);
            List<ContactTokenDetails> activeTokens = await this.pushServiceSocket.retrieveDirectory(contactTokensMap.Keys);

            foreach (ContactTokenDetails activeToken in activeTokens)
            {
                string number;
                contactTokensMap.TryGetValue(activeToken.getToken(), out number);
                activeToken.setNumber(number);
            }

            return activeTokens;
        }

        public async Task<string> getAccoountVerificationToken()
        {
            return await this.pushServiceSocket.getAccountVerificationToken();
        }

        public async Task<string> getNewDeviceVerificationCode()// throws IOException
        {
            return await this.pushServiceSocket.getNewDeviceVerificationCode();
        }

        public async void addDevice(string deviceIdentifier,
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
            await this.pushServiceSocket.sendProvisioningMessage(deviceIdentifier, ciphertext);
        }

        public async Task<List<DeviceInfo>> getDevices()
        {
            return await this.pushServiceSocket.getDevices();
        }

        public async void removeDevice(long deviceId)
        {
            await this.pushServiceSocket.removeDevice(deviceId);
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
}
