using CognitoAPI.Interfaces.DTO;

namespace CognitoUserManager.Contracts.DTO
{
    public class UpdateProfileResponse : BaseResponseModel
    {
        public string UserId { get; set; }
    }
}