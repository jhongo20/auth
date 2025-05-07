using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthSystem.Core.Entities
{
    // Definir las clases que faltan
    public class UserSession
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public string IPAddress { get; set; }
        public string UserAgent { get; set; }
        public string DeviceInfo { get; set; }
        public DateTime IssuedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public DateTime? RevokedAt { get; set; }
        public bool IsActive { get; set; } // Columna calculada
    }

    public class UserTwoFactorSettings
    {
        public Guid UserId { get; set; }
        public bool IsEnabled { get; set; }
        public string Method { get; set; } // Email, SMS, Authenticator
        public string SecretKey { get; set; }
        public string RecoveryCodesJson { get; set; }
        public DateTime UpdatedAt { get; set; }
    }

    public class PasswordHistory
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public string PasswordHash { get; set; }
        public DateTime ChangedAt { get; set; }
        public string IPAddress { get; set; }
        public string UserAgent { get; set; }
    }

    public class LoginAttempt
    {
        public Guid Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string IPAddress { get; set; }
        public string UserAgent { get; set; }
        public bool Successful { get; set; }
        public string FailureReason { get; set; }
        public DateTime AttemptedAt { get; set; }
        public Guid? UserId { get; set; }
    }

    public class AuditLog
    {
        public Guid Id { get; set; }
        public Guid? UserId { get; set; }
        public string Action { get; set; }
        public string EntityName { get; set; }
        public string EntityId { get; set; }
        public string OldValues { get; set; }
        public string NewValues { get; set; }
        public string IPAddress { get; set; }
        public string UserAgent { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
