using System;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IJwtService
    {
        Task<(string Token, string RefreshToken)> GenerateTokensAsync(User user, bool extendedDuration = false);
        Task<(bool IsValid, string UserId, string Jti)> ValidateTokenAsync(string token);
    }
}
