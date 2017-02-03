/** 
 * Copyright (C) 2015 smndtrl
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
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libsignalservice.push
{
    class PushTransportDetails
    {

        private static readonly String TAG = "PushTransportDetails";

        private readonly uint messageVersion;

        public PushTransportDetails(uint messageVersion)
        {
            this.messageVersion = messageVersion;
        }

        public byte[] getStrippedPaddingMessageBody(byte[] messageWithPadding)
        {
            if (messageVersion < 2) throw new Exception("Unknown version: " + messageVersion);
            else if (messageVersion == 2) return messageWithPadding;

            int paddingStart = 0;

            for (int i = messageWithPadding.Length - 1; i >= 0; i--)
            {
                if (messageWithPadding[i] == (byte)0x80)
                {
                    paddingStart = i;
                    break;
                }
                else if (messageWithPadding[i] != (byte)0x00)
                {
                    //Log.w(TAG, "Padding byte is malformed, returning unstripped padding.");
                    return messageWithPadding;
                }
            }

            byte[] strippedMessage = new byte[paddingStart];
            System.Buffer.BlockCopy(messageWithPadding, 0, strippedMessage, 0, strippedMessage.Length);

            return strippedMessage;
        }

        public byte[] getPaddedMessageBody(byte[] messageBody)
        {
            if (messageVersion < 2) throw new Exception("Unknown version: " + messageVersion);
            else if (messageVersion == 2) return messageBody;

            // NOTE: This is dumb.  We have our own padding scheme, but so does the cipher.
            // The +1 -1 here is to make sure the Cipher has room to add one padding byte,
            // otherwise it'll add a full 16 extra bytes.
            byte[] paddedMessage = new byte[getPaddedMessageLength(messageBody.Length + 1) - 1];
            System.Buffer.BlockCopy(messageBody, 0, paddedMessage, 0, messageBody.Length);
            paddedMessage[messageBody.Length] = (byte)0x80;

            return paddedMessage;
        }

        private int getPaddedMessageLength(int messageLength)
        {
            int messageLengthWithTerminator = messageLength + 1;
            int messagePartCount = messageLengthWithTerminator / 160;

            if (messageLengthWithTerminator % 160 != 0)
            {
                messagePartCount++;
            }

            return messagePartCount * 160;
        }
    }
}
