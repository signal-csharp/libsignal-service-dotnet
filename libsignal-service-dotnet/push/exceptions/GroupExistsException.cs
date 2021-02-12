namespace libsignalservice.push.exceptions
{
    public class GroupExistsException : NonSuccessfulResponseCodeException
    {
        public GroupExistsException() : base(409)
        {
        }
    }
}
