namespace libsignalservice.push.exceptions
{
    internal class GroupPatchNotAcceptedException : NonSuccessfulResponseCodeException
    {
        public GroupPatchNotAcceptedException() : base(400)
        {
        }
    }
}
