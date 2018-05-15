using Newtonsoft.Json;
using System;

namespace libsignalservice.util
{
    internal class JsonUtil
    {
        public static String ToJson(Object obje)
        {
            return JsonConvert.SerializeObject(obje);
        }

        public static T FromJson<T>(String json)
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
