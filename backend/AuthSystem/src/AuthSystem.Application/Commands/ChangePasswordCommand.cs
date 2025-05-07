using System;
using System.Threading;
using System.Threading.Tasks;
using AuthSystem.Application.DTOs;
using AuthSystem.Core.Interfaces;
using MediatR;
using Microsoft.Extensions.Logging;
using AuthSystem.Core.Exceptions;
using AuthSystem.Core.Constants;

namespace AuthSystem.Application.Commands.User
{
    public class ChangePasswordCommand : IRequest<ApiResponseDto<bool>>
    {
        public Guid UserId { get; set; }
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
    }

    public class ChangePasswordCommandHandler : IRequestHandler<ChangePasswordCommand, ApiResponseDto<bool>>
    {
        private readonly IUserRepository _userRepository;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IAuditService _auditService;
        private readonly ILogger<ChangePasswordCommandHandler> _logger;

        public ChangePasswordCommandHandler(
            IUserRepository userRepository,
            IPasswordHasher passwordHasher,
            IAuditService auditService,
            ILogger<ChangePasswordCommandHandler> logger)
        {
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
            _auditService = auditService;
            _logger = logger;
        }

        public async Task<ApiResponseDto<bool>> Handle(ChangePasswordCommand request, CancellationToken cancellationToken)
        {
            try
            {
                // 1. Obtener el usuario por ID
                var user = await _userRepository.GetByIdAsync(request.UserId);
                if (user == null)
                {
                    return ApiResponseDto<bool>.Failure("Usuario no encontrado", ErrorCodes.UserNotFound);
                }

                // 2. Validar la contraseña actual
                if (!_passwordHasher.VerifyPassword(user.PasswordHash, request.CurrentPassword))
                {
                    // Registrar intento fallido
                    if (_auditService != null)
                    {
                        await _auditService.LogActionAsync(
                            user.Id,
                            AuditConstants.PasswordChangeAction,
                            AuditConstants.UserEntity,
                            user.Id.ToString(),
                            null,
                            new { FailedAttempt = true, Reason = "Contraseña actual incorrecta" },
                            request.IpAddress,
                            request.UserAgent);
                    }

                    return ApiResponseDto<bool>.Failure("La contraseña actual es incorrecta", ErrorCodes.InvalidPassword);
                }

                // 3. Validar la nueva contraseña
                var validationErrors = ValidatePassword(request.NewPassword);
                if (validationErrors.Count > 0)
                {
                    return ApiResponseDto<bool>.Failure(validationErrors, ErrorCodes.ValidationError);
                }

                // 4. Verificar historial de contraseñas (si es necesario)
                if (await IsPasswordInHistoryAsync(user.Id, request.NewPassword))
                {
                    return ApiResponseDto<bool>.Failure(
                        "No se puede reutilizar una contraseña reciente. Por favor, elija una contraseña que no haya usado anteriormente.",
                        ErrorCodes.PasswordHistoryViolation);
                }

                // 5. Generar hash de la nueva contraseña
                var newPasswordHash = _passwordHasher.HashPassword(request.NewPassword);

                // 6. Actualizar la contraseña del usuario
                user.ChangePassword(newPasswordHash);
                await _userRepository.UpdateAsync(user);

                // 7. Registrar la contraseña en el historial
                await AddPasswordToHistoryAsync(user.Id, newPasswordHash, request.IpAddress, request.UserAgent);

                // 8. Revocar todas las sesiones activas (opcional)
                await _userRepository.RevokeAllUserSessionsAsync(user.Id);

                // 9. Guardar cambios
                //await _userRepository.SaveChangesAsync();
                await _userRepository.UpdateAsync(user);

                // 10. Registrar cambio de contraseña en auditoría
                if (_auditService != null)
                {
                    await _auditService.LogActionAsync(
                        user.Id,
                        AuditConstants.PasswordChangeAction,
                        AuditConstants.UserEntity,
                        user.Id.ToString(),
                        null,
                        new { Success = true, RequiredReset = user.RequirePasswordChange },
                        request.IpAddress,
                        request.UserAgent);
                }

                // 11. Retornar resultado exitoso
                return ApiResponseDto<bool>.Success(true, "Contraseña cambiada exitosamente");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al cambiar la contraseña del usuario {UserId}", request.UserId);
                return ApiResponseDto<bool>.Failure("Ha ocurrido un error al cambiar la contraseña. Por favor, inténtalo de nuevo más tarde.");
            }
        }

        private List<string> ValidatePassword(string password)
        {
            var errors = new List<string>();

            // Validar longitud mínima
            if (string.IsNullOrEmpty(password) || password.Length < SecurityConstants.MinPasswordLength)
            {
                errors.Add($"La contraseña debe tener al menos {SecurityConstants.MinPasswordLength} caracteres.");
            }

            // Validar longitud máxima
            if (password?.Length > SecurityConstants.MaxPasswordLength)
            {
                errors.Add($"La contraseña no debe exceder los {SecurityConstants.MaxPasswordLength} caracteres.");
            }

            // Validar si contiene al menos un dígito
            if (SecurityConstants.RequireDigit && !password.Any(char.IsDigit))
            {
                errors.Add(ValidationMessages.PasswordRequiresDigit);
            }

            // Validar si contiene al menos una letra minúscula
            if (SecurityConstants.RequireLowercase && !password.Any(char.IsLower))
            {
                errors.Add(ValidationMessages.PasswordRequiresLower);
            }

            // Validar si contiene al menos una letra mayúscula
            if (SecurityConstants.RequireUppercase && !password.Any(char.IsUpper))
            {
                errors.Add(ValidationMessages.PasswordRequiresUpper);
            }

            // Validar si contiene al menos un carácter no alfanumérico
            if (SecurityConstants.RequireNonAlphanumeric && password.All(c => char.IsLetterOrDigit(c)))
            {
                errors.Add(ValidationMessages.PasswordRequiresNonAlphanumeric);
            }

            return errors;
        }

        private async Task<bool> IsPasswordInHistoryAsync(Guid userId, string newPassword)
        {
            // Obtener historial de contraseñas recientes
            var passwordHistory = await _userRepository.GetPasswordHistoryAsync(userId, SecurityConstants.PasswordHistoryLimit);

            // Verificar si la nueva contraseña coincide con alguna del historial
            foreach (var historicPassword in passwordHistory)
            {
                if (_passwordHasher.VerifyPassword(historicPassword.PasswordHash, newPassword))
                {
                    return true;
                }
            }

            return false;
        }

        private async Task AddPasswordToHistoryAsync(Guid userId, string passwordHash, string ipAddress, string userAgent)
        {
            var passwordHistory = new Core.Entities.PasswordHistory
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                PasswordHash = passwordHash,
                ChangedAt = DateTime.UtcNow,
                IPAddress = ipAddress,
                UserAgent = userAgent
            };

            await _userRepository.AddPasswordToHistoryAsync(passwordHistory);
        }
    }
}