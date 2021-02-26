using System;
using Newtonsoft.Json;

namespace libsignalservice.util
{
    internal class JsonUtil
    {
        public static string ToJson(object obje)
        {
            return JsonConvert.SerializeObject(obje);
        }

        public static T FromJson<T>(string json)
        {
            try
            {
                return JsonConvert.DeserializeObject<T>(json);
            }
            catch (Exception e)
            {
                throw new JsonParseException(e);
            }
        }
    }
}
