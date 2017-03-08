﻿/** 
 * Copyright (C) 2017 smndtrl, golf1052
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
using System.Text;
using libsignal.ecc;
using libsignal.kdf;
using libsignalservice.util;
using libsignalservice.push;
using Google.Protobuf;
using System.Security.Cryptography;

namespace libsignalservice.crypto
{
    class ProvisioningCipher
    {
        private static readonly String TAG = "ProvisioningCipher";

        private readonly ECPublicKey theirPublicKey;

        public ProvisioningCipher(ECPublicKey theirPublicKey)
        {
            this.theirPublicKey = theirPublicKey;
        }

        public byte[] encrypt(ProvisionMessage message)// throws InvalidKeyException
        {
            ECKeyPair ourKeyPair = Curve.generateKeyPair();
            byte[] sharedSecret = Curve.calculateAgreement(theirPublicKey, ourKeyPair.getPrivateKey());
            byte[] derivedSecret = new HKDFv3().deriveSecrets(sharedSecret, Encoding.UTF8.GetBytes("TextSecure Provisioning Message"), 64);
            byte[][] parts = Util.split(derivedSecret, 32, 32);

            byte[] version = { 0x01 };
            byte[] ciphertext = getCiphertext(parts[0], message.ToByteArray());
            byte[] mac = getMac(parts[1], Util.join(version, ciphertext));
            byte[] body = Util.join(version, ciphertext, mac);

            return new ProvisionEnvelope
            {
                PublicKey = ByteString.CopyFrom(ourKeyPair.getPublicKey().serialize()),
                Body = ByteString.CopyFrom(body)
            }.ToByteArray();
        }

        private byte[] getCiphertext(byte[] key, byte[] message)
        {
            try
            {
                using (var aes = Aes.Create())
                using (var enc = aes.CreateEncryptor())
                {
                    aes.BlockSize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = key;
                    return Util.join(aes.IV, enc.TransformFinalBlock(message, 0, message.Length));
                }
            }
            catch (/*NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException | IllegalBlockSizeException | BadPaddingException*/ Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        private byte[] getMac(byte[] key, byte[] message)
        {
            try
            {
                HMACSHA256 mac = new HMACSHA256();
                mac.Key = key;
                return mac.ComputeHash(message);
            }
            catch (/*NoSuchAlgorithmException | java.security.InvalidKeyException*/Exception e) {
                throw new Exception(e.Message);
            }
            }

        }
    }