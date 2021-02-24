using System.Collections.Generic;

namespace libsignalservice.messages
{
    public class SignalServiceStickerManifest
    {
        public string? Title { get; }
        public string? Author { get; }
        public StickerInfo? Cover { get; }
        public List<StickerInfo> Stickers { get; }

        public SignalServiceStickerManifest(string title, string author, StickerInfo? cover, List<StickerInfo>? stickers)
        {
            Title = title;
            Author = author;
            Cover = cover;
            Stickers = stickers == null ? new List<StickerInfo>() : stickers;
        }
        
        public class StickerInfo
        {
            public int Id { get; }
            public string Emoji { get; }

            public StickerInfo(int id, string emoji)
            {
                Id = id;
                Emoji = emoji;
            }
        }
    }
}
