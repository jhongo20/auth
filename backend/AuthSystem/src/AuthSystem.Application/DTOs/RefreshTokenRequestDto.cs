using System.ComponentModel.DataAnnotations;

namespace AuthSystem.Application.DTOs
{
    public class RefreshTokenRequestDto
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}