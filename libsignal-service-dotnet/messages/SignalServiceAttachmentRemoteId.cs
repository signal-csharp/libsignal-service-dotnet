using System;
using libsignal;
using libsignalmetadatadotnet;
using libsignalservice.push;

namespace libsignalservice.messages
{
    public class SignalServiceAttachmentRemoteId
    {
        public long? V2 { get; }
        public string? V3 { get; }

        public SignalServiceAttachmentRemoteId(long v2)
        {
            V2 = v2;
            V3 = null;
        }

        public SignalServiceAttachmentRemoteId(string v3)
        {
            V2 = null;
            V3 = v3;
        }

        public override string ToString()
        {
            if (V2.HasValue)
            {
                return V2.Value.ToString();
            }
            else
            {
                return V3!;
            }
        }

        public static SignalServiceAttachmentRemoteId? From(AttachmentPointer attachmentPointer)
        {
            switch (attachmentPointer.AttachmentIdentifierCase)
            {
                case AttachmentPointer.AttachmentIdentifierOneofCase.CdnId:
                    return new SignalServiceAttachmentRemoteId((long)attachmentPointer.CdnId);
                case AttachmentPointer.AttachmentIdentifierOneofCase.CdnKey:
                    return new SignalServiceAttachmentRemoteId(attachmentPointer.CdnKey);
                case AttachmentPointer.AttachmentIdentifierOneofCase.None:
                    throw new ProtocolInvalidMessageException(new InvalidMessageException("AttachmentPointer CDN location not set"), null!, 0);
            }
            return null;
        }

        public static SignalServiceAttachmentRemoteId From(string str)
        {
            try
            {
                return new SignalServiceAttachmentRemoteId(long.Parse(str));
            }
            catch (FormatException)
            {
                return new SignalServiceAttachmentRemoteId(str);
            }
        }
    }
}
