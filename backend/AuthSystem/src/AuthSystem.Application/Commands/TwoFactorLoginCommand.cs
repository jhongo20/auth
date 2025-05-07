using System;
using System.Threading;
using System.Threading.Tasks;
using AuthSystem.Application.DTOs;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Enums;
using AuthSystem.Core.Interfaces;
using MediatR;
using Microsoft.Extensions.Logging;
using AutoMapper;

namespace AuthSystem.Application.Commands.Authentication
{
    public class TwoFactorLoginCommand : IRequest<AuthResponseDto>
    {
        public Guid UserId { get; set; }
        public string Code { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public bool RememberMe { get; set; }
    }

    public class TwoFactorLoginCommandHandler : IRequestHandler<TwoFactorLoginCommand, AuthResponseDto>
    {
        private readonly IUserRepository _userRepository;
        private readonly ITotpService _totpService;
        private readonly IJwtService _jwtService;
        private readonly IAuditService _auditService;
        private readonly IMapper _mapper;
        private readonly ILogger<TwoFactorLoginCommandHandler> _logger;

        public TwoFactorLoginCommandHandler(
            IUserRepository userRepository,
            ITotpService totpService,
            IJwtService jwtService,
            IAuditService auditService,
            IMapper mapper,
            ILogger<TwoFactorLoginCommandHandler> logger)
        {
            _userRepository = userRepository;
            _totpService = totpService;
            _jwtService = jwtService;
            _auditService = auditService;
            _mapper = mapper;
            _logger = logger;
        }

        public async Task<AuthResponseDto> Handle(TwoFactorLoginCommand request, CancellationToken cancellationToken)
        {
            try
            {
                // 1. Obtener el usuario por ID
                var user = await _userRepository.GetByIdAsync(request.UserId);
                if (user == null)
                {
                    await LogFailedLoginAttempt(request, "Usuario no encontrado", null);
                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = "Usuario no encontrado. Por favor, inicie sesión nuevamente."
                    };
                }

                // 2. Verificar el estado del usuario
                if (user.Status != UserStatus.Active)
                {
                    string errorMessage;
                    switch (user.Status)
                    {
                        case UserStatus.Registered:
                            errorMessage = "La cuenta no ha sido activada. Por favor, revisa tu correo electrónico para activar la cuenta.";
                            break;
                        case UserStatus.Blocked:
                            errorMessage = "Esta cuenta ha sido bloqueada. Por favor, contacta con soporte para más información.";
                            break;
                        case UserStatus.Suspended:
                            errorMessage = "Esta cuenta ha sido suspendida temporalmente.";
                            break;
                        case UserStatus.Deleted:
                            errorMessage = "Esta cuenta ha sido eliminada.";
                            break;
                        default:
                            errorMessage = "La cuenta no está activa.";
                            break;
                    }

                    await LogFailedLoginAttempt(request, $"Usuario con estado {user.Status}", user.Id);
                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = errorMessage
                    };
                }

                // 3. Verificar si la cuenta tiene 2FA habilitado
                if (!user.TwoFactorEnabled)
                {
                    await LogFailedLoginAttempt(request, "2FA no habilitado", user.Id);
                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = "La autenticación de dos factores no está habilitada para esta cuenta."
                    };
                }

                // 4. Obtener la configuración de 2FA
                var twoFactorSettings = await _userRepository.GetTwoFactorSettingsAsync(user.Id);
                if (twoFactorSettings == null)
                {
                    await LogFailedLoginAttempt(request, "Configuración 2FA no encontrada", user.Id);
                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = "Error en la configuración de autenticación de dos factores. Por favor, contacte con soporte."
                    };
                }

                // 5. Validar el código según el método configurado
                bool isValidCode = false;
                switch (twoFactorSettings.Method)
                {
                    case "Authenticator":
                        // Verificar con TOTP para aplicaciones autenticadoras
                        isValidCode = _totpService.ValidateCode(twoFactorSettings.SecretKey, request.Code);
                        break;

                    case "Email":
                    case "SMS":
                        // Para Email/SMS, se utiliza un código de un solo uso almacenado temporalmente
                        // Normalmente se usaría Redis o similar para almacenar estos códigos temporales
                        // Aquí simulamos la verificación (en una implementación real, se consultaría un almacenamiento temporal)
                        var cachedCode = await GetCachedVerificationCodeAsync(user.Id, twoFactorSettings.Method);
                        isValidCode = (cachedCode != null && cachedCode == request.Code);
                        break;

                    case "RecoveryCode":
                        // Verificar contra los códigos de recuperación guardados
                        if (!string.IsNullOrEmpty(twoFactorSettings.RecoveryCodesJson))
                        {
                            var recoveryCodes = System.Text.Json.JsonSerializer.Deserialize<string[]>(twoFactorSettings.RecoveryCodesJson);
                            if (recoveryCodes != null && recoveryCodes.Contains(request.Code))
                            {
                                isValidCode = true;

                                // Eliminar el código de recuperación utilizado
                                var updatedCodes = recoveryCodes.Where(c => c != request.Code).ToArray();
                                twoFactorSettings.RecoveryCodesJson = System.Text.Json.JsonSerializer.Serialize(updatedCodes);
                                await _userRepository.SaveTwoFactorSettingsAsync(twoFactorSettings);
                            }
                        }
                        break;

                    default:
                        await LogFailedLoginAttempt(request, $"Método 2FA desconocido: {twoFactorSettings.Method}", user.Id);
                        return new AuthResponseDto
                        {
                            Succeeded = false,
                            Error = "Método de autenticación de dos factores no soportado."
                        };
                }

                // 6. Si el código es inválido, registrar el fallo y retornar error
                if (!isValidCode)
                {
                    await LogFailedLoginAttempt(request, "Código 2FA inválido", user.Id);
                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = "Código de verificación inválido. Por favor, inténtelo de nuevo."
                    };
                }

                // 7. Actualizar el contador de intentos fallidos y fecha de último login
                user.ResetAccessFailedCount();
                user.UpdateLastLoginDate();
                await _userRepository.UpdateAsync(user);
                //await _userRepository.SaveChangesAsync();

                // 8. Generar tokens JWT
                var (token, refreshToken) = await _jwtService.GenerateTokensAsync(user, request.RememberMe);

                // 9. Registrar nueva sesión
                var sessionId = Guid.NewGuid();
                await _userRepository.AddSessionAsync(new UserSession
                {
                    Id = sessionId,
                    UserId = user.Id,
                    Token = token,
                    RefreshToken = refreshToken,
                    IPAddress = request.IpAddress,
                    UserAgent = request.UserAgent,
                    DeviceInfo = ExtractDeviceInfo(request.UserAgent),
                    IssuedAt = DateTime.UtcNow,
                    ExpiresAt = request.RememberMe ? DateTime.UtcNow.AddDays(7) : DateTime.UtcNow.AddHours(2)
                });

                // 10. Registrar login exitoso en auditoría
                await LogSuccessfulLoginAttempt(request, user.Id);

                // 11. Mapear usuario a DTO
                var userDto = _mapper.Map<UserDto>(user);

                // 12. Obtener roles y permisos
                var roles = await _userRepository.GetUserRolesAsync(user.Id);
                var permissions = await _userRepository.GetUserPermissionsAsync(user.Id);

                userDto.Roles = roles.Select(r => r.Name).ToList();
                userDto.Permissions = permissions.Select(p => p.Code).ToList();

                // 13. Devolver respuesta exitosa
                return new AuthResponseDto
                {
                    Succeeded = true,
                    Token = token,
                    RefreshToken = refreshToken,
                    RequirePasswordChange = user.RequirePasswordChange,
                    User = userDto,
                    Message = "Inicio de sesión exitoso"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante la autenticación de dos factores para el usuario {UserId}", request.UserId);
                return new AuthResponseDto
                {
                    Succeeded = false,
                    Error = "Ha ocurrido un error durante la autenticación de dos factores. Por favor, inténtelo de nuevo más tarde."
                };
            }
        }

        private async Task<string> GetCachedVerificationCodeAsync(Guid userId, string method)
        {
            // En una implementación real, este código se obtendría de un almacenamiento en caché como Redis
            // Para este ejemplo, simplemente devolvemos un código fijo para simular la funcionalidad

            // En producción, usarías algo como:
            // return await _cacheService.GetAsync<string>($"2FA:{userId}:{method}");

            return "123456"; // Código de ejemplo para pruebas
        }

        private async Task LogFailedLoginAttempt(TwoFactorLoginCommand request, string reason, Guid? userId)
        {
            if (_auditService != null)
            {
                await _auditService.LogLoginAttemptAsync(
                    userId.HasValue ? (await _userRepository.GetByIdAsync(userId.Value))?.Username : "N/A",
                    request.IpAddress,
                    request.UserAgent,
                    false,
                    $"2FA: {reason}",
                    userId);
            }
        }

        private async Task LogSuccessfulLoginAttempt(TwoFactorLoginCommand request, Guid userId)
        {
            if (_auditService != null)
            {
                var username = (await _userRepository.GetByIdAsync(userId))?.Username;
                await _auditService.LogLoginAttemptAsync(
                    username,
                    request.IpAddress,
                    request.UserAgent,
                    true,
                    "2FA completado exitosamente",
                    userId);
            }
        }

        private string ExtractDeviceInfo(string userAgent)
        {
            // Implementación simple para extraer información del dispositivo
            // En una implementación real, se utilizaría una biblioteca especializada
            if (string.IsNullOrEmpty(userAgent))
                return "Unknown";

            string deviceInfo = "Unknown";

            if (userAgent.Contains("Windows"))
                deviceInfo = "Windows";
            else if (userAgent.Contains("Mac"))
                deviceInfo = "Mac";
            else if (userAgent.Contains("Android"))
                deviceInfo = "Android";
            else if (userAgent.Contains("iPhone") || userAgent.Contains("iPad"))
                deviceInfo = "iOS";
            else if (userAgent.Contains("Linux"))
                deviceInfo = "Linux";

            // Extraer el navegador
            string browser = "Unknown";
            if (userAgent.Contains("Chrome") && !userAgent.Contains("Chromium"))
                browser = "Chrome";
            else if (userAgent.Contains("Firefox"))
                browser = "Firefox";
            else if (userAgent.Contains("Safari") && !userAgent.Contains("Chrome"))
                browser = "Safari";
            else if (userAgent.Contains("Edge"))
                browser = "Edge";
            else if (userAgent.Contains("MSIE") || userAgent.Contains("Trident"))
                browser = "Internet Explorer";

            return $"{deviceInfo} - {browser}";
        }
    }
}