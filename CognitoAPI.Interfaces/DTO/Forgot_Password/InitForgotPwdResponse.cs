namespace CognitoAPI.Interfaces.DTO
{
    public class InitForgotPwdResponse : BaseResponseModel
    {
        public string UserId { get; set; }
        public string EmailAddress { get; set; }
    }
}