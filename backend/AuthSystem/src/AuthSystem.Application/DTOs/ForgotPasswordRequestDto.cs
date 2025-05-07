using System.ComponentModel.DataAnnotations;

namespace AuthSystem.Application.DTOs
{
    public class ForgotPasswordRequestDto
    {
        [Required(ErrorMessage = "El correo electrónico es obligatorio")]
        [EmailAddress(ErrorMessage = "El formato del correo electrónico no es válido")]
        public string Email { get; set; }
    }
}