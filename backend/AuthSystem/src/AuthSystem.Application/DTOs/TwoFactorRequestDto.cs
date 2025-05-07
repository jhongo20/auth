using System;
using System.ComponentModel.DataAnnotations;

namespace AuthSystem.Application.DTOs
{
    public class TwoFactorRequestDto
    {
        [Required]
        public Guid UserId { get; set; }

        [Required]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "El código debe tener 6 dígitos")]
        public string Code { get; set; }

        public bool RememberMe { get; set; }
    }
}