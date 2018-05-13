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

using libsignaldotnet.push.http;
using System;
using System.IO;
using static libsignalservice.messages.SignalServiceAttachment;

namespace libsignalservice.push
{
    public class PushAttachmentData
    {
        public string ContentType { get; }
        public Stream Data { get; }
        public ulong DataSize { get; }
        public OutputStreamFactory OutputFactory { get; }
        public ProgressListener Listener { get; }

        public PushAttachmentData(String contentType, Stream data, ulong dataSize, OutputStreamFactory outputStreamFactory, ProgressListener listener)
        {
            ContentType = contentType;
            Data = data;
            DataSize = dataSize;
            OutputFactory = outputStreamFactory;
            Listener = listener;
        }
    }
}
