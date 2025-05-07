using System.ComponentModel.DataAnnotations;

namespace AuthSystem.Application.DTOs
{
    public class LoginRequestDto
    {
        [Required(ErrorMessage = "El nombre de usuario es obligatorio")]
        public string Username { get; set; }

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        public string Password { get; set; }

        public bool RememberMe { get; set; }

        public string RecaptchaToken { get; set; }
    }
}