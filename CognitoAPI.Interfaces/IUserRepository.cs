using CognitoAPI.Interfaces.DTO;
using CognitoUserManager.Contracts.DTO;
using System.Threading.Tasks;

namespace CognitoAPI.Interfaces.Repositories
{
    public interface IUserRepository
    {
        Task<UserSignUpResponse> ConfirmUserSignUpAsync(UserConfirmSignUpModel model);
        Task<UserSignUpResponse> CreateUserAsync(UserSignUpModel model);
        Task<UserProfileResponse> GetUserAsync(string token);
        Task<BaseResponseModel> TryChangePasswordAsync(ChangePwdModel model);
        Task<InitForgotPwdResponse> TryInitForgotPasswordAsync(InitForgotPwdModel model);
        Task<AuthResponseModel> TryLoginAsync(UserLoginModel model);
        Task<UserSignOutResponse> TryLogOutAsync(UserSignOutModel model);
        Task<ResetPasswordResponse> TryResetPasswordWithConfirmationCodeAsync(ResetPasswordModel model);
        Task<UpdateProfileResponse> UpdateUserAttributesAsync(UpdateProfileModel model);
    }
}