// Agregar a AuthSystem.Core/Entities/EmailConfirmationToken.cs
using System;

namespace AuthSystem.Core.Entities
{
    public class EmailConfirmationToken
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public string Token { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }

        // Navegación
        public User User { get; set; }
    }
}