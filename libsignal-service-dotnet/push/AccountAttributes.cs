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

using Newtonsoft.Json;

namespace libsignalservice.push
{
    [JsonObject(MemberSerialization.OptIn)]
    internal class AccountAttributes
    {
        [JsonProperty("signalingKey", Required = Required.Always)]
        private string SignalingKey { get; set; }

        [JsonProperty("registrationId", Required = Required.Always)]
        private uint RegistrationId { get; set; }

        [JsonProperty("voice", Required = Required.Always)]
        private bool Voice { get; set; }

        [JsonProperty("video", Required = Required.Always)]
        private bool Video { get; set; }

        [JsonProperty("fetchesMessages", Required = Required.Always)]
        private bool FetchesMessages { get; set; }

        public AccountAttributes()
        {
        }

        public AccountAttributes(string signalingKey, uint registrationId, bool voice)
        {
            SignalingKey = signalingKey;
            RegistrationId = registrationId;
            Voice = voice;
        }

        public AccountAttributes(string signalingKey, uint registrationId, bool voice, bool video, bool fetchesMessages)
        {
            SignalingKey = signalingKey;
            RegistrationId = registrationId;
            Voice = voice;
            Video = video;
            FetchesMessages = fetchesMessages;
        }
    }
}
