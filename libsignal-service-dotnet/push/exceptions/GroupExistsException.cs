namespace libsignalservice.push.exceptions
{
    internal class GroupExistsException : NonSuccessfulResponseCodeException
    {
        public GroupExistsException() : base(409)
        {
        }
    }
}
