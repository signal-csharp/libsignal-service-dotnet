using System;

namespace libsignalservice.push
{
    internal class PushTransportDetails
    {
        private readonly uint messageVersion;

        public PushTransportDetails(uint messageVersion)
        {
            this.messageVersion = messageVersion;
        }

        public byte[] GetStrippedPaddingMessageBody(byte[] messageWithPadding)
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
