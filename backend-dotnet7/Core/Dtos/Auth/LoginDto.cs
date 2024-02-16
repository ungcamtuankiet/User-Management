using System.ComponentModel.DataAnnotations;

namespace backend_dotnet7.Core.Dtos.Auth
{
    public class LoginDto
    {
        [Required(ErrorMessage = "UserName is requird")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Password is requird")]
        public string Password { get; set; }
    }
}
