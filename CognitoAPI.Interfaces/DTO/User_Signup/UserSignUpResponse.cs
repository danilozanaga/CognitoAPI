namespace CognitoAPI.Interfaces.DTO
{
    public class UserSignUpResponse : BaseResponseModel
    {
        public string UserId { get; set; }
        public string EmailAddress { get; set; }
    }
}