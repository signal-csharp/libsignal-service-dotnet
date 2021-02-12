namespace libsignalservice.push.exceptions
{
    public class GroupPatchNotAcceptedException : NonSuccessfulResponseCodeException
    {
        public GroupPatchNotAcceptedException() : base(400)
        {
        }
    }
}
