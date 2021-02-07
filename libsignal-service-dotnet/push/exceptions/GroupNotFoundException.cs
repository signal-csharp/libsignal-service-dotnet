namespace libsignalservice.push.exceptions
{
    internal class GroupNotFoundException : NonSuccessfulResponseCodeException
    {
        public GroupNotFoundException() : base(404)
        {
        }
    }
}
