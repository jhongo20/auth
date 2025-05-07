using System.ComponentModel.DataAnnotations;

namespace AuthSystem.Application.DTOs
{
    public class RegisterRequestDto
    {
        [Required(ErrorMessage = "El nombre de usuario es obligatorio")]
        [MinLength(4, ErrorMessage = "El nombre de usuario debe tener al menos 4 caracteres")]
        public string Username { get; set; }

        [Required(ErrorMessage = "El correo electrónico es obligatorio")]
        [EmailAddress(ErrorMessage = "El formato del correo electrónico no es válido")]
        public string Email { get; set; }

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        [MinLength(8, ErrorMessage = "La contraseña debe tener al menos 8 caracteres")]
        public string Password { get; set; }

        [Compare("Password", ErrorMessage = "Las contraseñas no coinciden")]
        public string ConfirmPassword { get; set; }

        public string FirstName { get; set; }

        public string LastName { get; set; }

        public string RecaptchaToken { get; set; }
    }
}