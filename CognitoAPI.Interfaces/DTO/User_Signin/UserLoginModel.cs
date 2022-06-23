using System.ComponentModel.DataAnnotations;

namespace CognitoAPI.Interfaces.DTO
{
    public class UserLoginModel
    {
        [Required]
        public string EmailAddress { get; set; }

        [Required]
        public string Password { get; set; }

        [Required]
        public string AppId { get; set; }

    }
}