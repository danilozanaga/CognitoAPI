using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using CognitoAPI.Interfaces;
using CognitoAPI.Interfaces.DTO;
using CognitoAPI.Interfaces.Repositories;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;

namespace CognitoAPI.Controllers
{

    [ApiController]
    [Route("[controller]")]
    public class UserController : Controller
    {
        public const string Session_TokenKey = "_Tokens";
        private readonly IUserRepository _userService;

        public UserController(IUserRepository userService)
        {
            _userService = userService;
        }

        //#region Landing-TokensPage

        //[System.Web.Http.Authorize]
        //public async Task<IActionResult> IndexAsync()
        //{
        //    var id = User.Claims.Where(x => x.Type == ClaimTypes.NameIdentifier).First();
        //    var response = await _userService.GetUserAsync(id.Value);

        //    var model = new UpdateProfileModel
        //    {
        //        UserId = id.Value,
        //        GivenName = response.GivenName,
        //        PhoneNumber = response.PhoneNumber,
        //        Pincode = response.Address.GetOrDefaultValue("postal_code"),
        //        Country = response.Address.GetOrDefaultValue("country"),
        //        State = response.Address.GetOrDefaultValue("region"),
        //        Address = response.Address.GetOrDefaultValue("street_address"),
        //        Gender = response.Gender
        //    };

        //    return Ok(model);
        //}

        //[System.Web.Http.Authorize]
        //[System.Web.Http.HttpPost]
        //public async Task<IActionResult> IndexAsync(UpdateProfileModel model)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return View();
        //    }

        //    var userId = User.Claims.Where(x => x.Type == ClaimTypes.NameIdentifier).First();

        //    var token = _cache.Get<TokenModel>($"{userId.Value}_{Session_TokenKey}");

        //    model.AccessToken = token.AccessToken;

        //    var response = await _userService.UpdateUserAttributesAsync(model);

        //    if (response.IsSuccess)
        //    {
        //        return RedirectToAction("Index", "Home");
        //    }

        //    return View();
        //}

        //#endregion

        [HttpPost("getuser")]
        public async Task<UserProfileResponse> GetUserAsync(string token)
        {
            UserProfileResponse response = await _userService.GetUserAsync(token);
            if (response.IsSuccess)
            {
                return response;
            }

            return response;

        }


        #region ExistingUser-Login

        //public IActionResult Login()
        //{
        //    return Ok();
        //}


        [HttpPost("getdata")]
        public async Task<ActionResult> GetData()
        {
            var cookies = HttpContext.Request.Cookies;
            if (cookies.ContainsKey("Token"))
            {
                return Ok("Sucesso");
            } else
            {
                return StatusCode(401, "Unauthorized");
            }
        }


        [HttpPost("trylogin")]
        public async Task<ActionResult> LoginAsync(UserLoginModel model)
        {
            var cookies = HttpContext.Request.Cookies;

            var response = await _userService.TryLoginAsync(model);
            TimeSpan _time = DateTime.Now.TimeOfDay;
            TokenModel _token = new TokenModel();
            if (response.IsSuccess)
            {
                CookieOptions options = new CookieOptions
                {
                    Domain = "localhost",
                    MaxAge = new TimeSpan(1,0,0),
                    HttpOnly = true,
                    Secure = true,
                    Path = "/"
                };

                HttpContext.Response.Cookies.Append("Token", response.Tokens.AccessToken,options);
                HttpContext.Response.Cookies.Append("UserId", model.EmailAddress, options);
                HttpContext.Response.Cookies.Append("AppId", model.AppId, options);

                _token = response.Tokens;
                return Ok(_token);
            }

            return StatusCode(500,response.Message);

        }

        #endregion

        #region NewUser-Signup

        [HttpPost("signup")]
        public async Task<ActionResult> SignupAsync(UserSignUpModel model)
        {

            var response = await _userService.CreateUserAsync(model);

            if (response.IsSuccess)
            {
                return Ok(response);
            }

            return StatusCode(500,response.Message);
        }

        [HttpPost("confirmsignup")]
        public async Task<ActionResult> ConfirmSignupAsync(UserConfirmSignUpModel model)
        {
            var response = await _userService.ConfirmUserSignUpAsync(model);

            if (response.IsSuccess)
            {
                return Ok(model);
            }

            return StatusCode(500,response.Message);
        }

        #endregion

        #region Change-Password

        [Authorize]
        [HttpPost("changepassoword")]
        public async Task<ActionResult> ChangePassword(ChangePwdModel model)
        {
            var response = await _userService.TryChangePasswordAsync(model);

            if (response.IsSuccess)
            {
                return Ok(model);
            }

            return Ok(model);
        }

        #endregion

        [HttpPost("logout")]
        public async Task<IActionResult> LogOutAsync()
        {
            var cookies = HttpContext.Request.Cookies;
            if (cookies.ContainsKey("Token") && (cookies["AppId"] != "" )) 
            {
                var user = new UserSignOutModel
                {
                    AccessToken = cookies["Token"],
                    UserId = cookies["UserId"]
                };
                await _userService.TryLogOutAsync(user);
                CookieOptions options = new CookieOptions
                {
                    Domain = "localhost",
                    MaxAge = new TimeSpan(0, 0, 0),
                    HttpOnly = true,
                    Secure = true,
                    Path = "/"
                };

                HttpContext.Response.Cookies.Append("Token", user.AccessToken, options); ;
                HttpContext.Response.Cookies.Append("UserId", user.UserId, options);
                HttpContext.Response.Cookies.Append("AppId", "", options);
                return StatusCode(200, "Disconnected");
            }
            
            return StatusCode(500, "No data found for logged user");
        }

        #region Forgot-Password

        [Microsoft.AspNetCore.Mvc.HttpPost("forgotpassword")]
        public async Task<ActionResult> ForgotPasswordAsync(InitForgotPwdModel model)
        {

            var response = await _userService.TryInitForgotPasswordAsync(model);

            if (response.IsSuccess)
            {
                //TempData["EmailAddress"] = response.EmailAddress;
                //TempData["UserId"] = response.UserId;

                return Ok(model);
            }

            return Ok(model);
        }

        [HttpPost("ResetPasswordWithConfirmationCode")]
        public async Task<ActionResult> ResetPasswordWithConfirmationCodeAsync(ResetPasswordModel model)
        {

            var response = await _userService.TryResetPasswordWithConfirmationCodeAsync(model);

            if (response.IsSuccess)
            {
                return Ok(model);
            }

            return Ok(model);
        }

        #endregion
    }

    public static class SessionExtensions
    {
        public static K GetOrDefaultValue<T, K>(this Dictionary<T, K> dictionary, T key)
        {
            return dictionary.ContainsKey(key) ? dictionary[key] : default;
        }
    }
}