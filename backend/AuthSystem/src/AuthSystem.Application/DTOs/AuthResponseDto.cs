using System;

namespace AuthSystem.Application.DTOs
{
    public class AuthResponseDto
    {
        public bool Succeeded { get; set; }
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public bool RequiresTwoFactor { get; set; }
        public Guid? UserId { get; set; }
        public bool RequirePasswordChange { get; set; }
        public string Error { get; set; }
        public string Message { get; set; } // Añadido aquí
        public UserDto User { get; set; }
    }
}