using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IUserRepository
    {
        Task<User> GetByIdAsync(Guid id);
        Task<User> GetByUsernameAsync(string username);
        Task<User> GetByEmailAsync(string email);
        Task<User> FindByUsernameOrEmailAsync(string usernameOrEmail);
        Task<IEnumerable<User>> GetAllAsync();
        Task<User> CreateAsync(User user);
        Task UpdateAsync(User user);
        Task DeleteAsync(Guid id);
        Task<bool> UsernameExistsAsync(string username);
        Task<bool> EmailExistsAsync(string email);
        Task<(bool IsValid, User User)> ValidateCredentialsAsync(string username, string password);
        Task<(bool IsValid, User User)> ValidateCredentialsByEmailAsync(string email, string password);
        
        // Métodos para roles y permisos
        Task<IReadOnlyList<Role>> GetUserRolesAsync(Guid userId);
        Task<IReadOnlyList<Permission>> GetUserPermissionsAsync(Guid userId);
        Task<bool> AddToRoleAsync(Guid userId, Guid roleId, Guid? assignedBy = null);
        Task<bool> RemoveFromRoleAsync(Guid userId, Guid roleId);
        Task<bool> AddPermissionAsync(Guid userId, Guid permissionId, bool isGranted = true, Guid? assignedBy = null);
        Task<bool> RemovePermissionAsync(Guid userId, Guid permissionId);
        Task<bool> IsInRoleAsync(Guid userId, Guid roleId);
        Task<bool> HasPermissionAsync(Guid userId, Guid permissionId);
        Task<Role> GetRoleByNameAsync(string roleName);
        
        // Métodos para sesiones
        Task AddSessionAsync(UserSession session);
        Task<bool> RevokeSessionAsync(Guid sessionId);
        Task<bool> RevokeAllUserSessionsAsync(Guid userId);
        Task<bool> IsTokenRevokedAsync(Guid userId, string jti);
        
        // Métodos para autenticación de dos factores
        Task<UserTwoFactorSettings> GetTwoFactorSettingsAsync(Guid userId);
        Task SaveTwoFactorSettingsAsync(UserTwoFactorSettings settings);
        Task RemoveTwoFactorSettingsAsync(Guid userId);
        
        // Métodos para confirmación de email
        Task SaveEmailConfirmationTokenAsync(EmailConfirmationToken token);
        Task<EmailConfirmationToken> GetEmailConfirmationTokenAsync(Guid userId, string token);
        Task DeleteEmailConfirmationTokenAsync(Guid tokenId);
        Task DeleteAllEmailConfirmationTokensForUserAsync(Guid userId);
        Task StoreEmailConfirmationTokenAsync(Guid userId, string token);
        Task<(bool IsValid, User User)> ValidateEmailConfirmationTokenAsync(Guid userId, string token);
        Task<bool> ConfirmEmailAsync(Guid userId);
        
        // Métodos para historial de contraseñas
        Task<IReadOnlyList<PasswordHistory>> GetPasswordHistoryAsync(Guid userId, int limit);
        Task AddPasswordToHistoryAsync(PasswordHistory passwordHistory);
    }
}
