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
        private string SignalingKey { get; }

        [JsonProperty("registrationId", Required = Required.Always)]
        private uint RegistrationId { get; }

        [JsonProperty("voice", Required = Required.Always)]
        private bool Voice { get; }

        [JsonProperty("video", Required = Required.Always)]
        private bool Video { get; }

        [JsonProperty("fetchesMessages", Required = Required.Always)]
        private bool FetchesMessages { get; }

        [JsonProperty("pin")]
        private string Pin { get; }

        public AccountAttributes(string signalingKey, uint registrationId, bool fetchesMessages, string pin)
        {
            SignalingKey = signalingKey;
            RegistrationId = registrationId;
            Voice = true;
            Video = true;
            FetchesMessages = fetchesMessages;
            Pin = pin;
        }
    }
}
