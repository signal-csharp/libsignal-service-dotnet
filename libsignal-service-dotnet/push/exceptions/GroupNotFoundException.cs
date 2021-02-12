namespace libsignalservice.push.exceptions
{
    public class GroupNotFoundException : NonSuccessfulResponseCodeException
    {
        public GroupNotFoundException() : base(404)
        {
        }
    }
}
