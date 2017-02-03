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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libsignalservice.util
{
    class JsonUtil
    {/*

        private static readonly String TAG = "JsonUtil";

        private static readonly ObjectMapper objectMapper = new ObjectMapper();

        /*        static {
            objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
          }
          */
        public static String toJson(Object obje)
        {
            try
            {
                return JsonConvert.SerializeObject(obje);
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
                return "";
            }
        }
        
        public static T fromJson<T>(String json)
        {
            try
            {
                return JsonConvert.DeserializeObject<T>(json);
            }
            catch (Exception e)
            {
                //Log.w(TAG, e);
                throw new JsonParseException(e);
            }
        }
        
        public class JsonParseException : Exception
        {
            public JsonParseException(Exception e)
                : base(e.Message)
            {
            }
        }

    }
}
