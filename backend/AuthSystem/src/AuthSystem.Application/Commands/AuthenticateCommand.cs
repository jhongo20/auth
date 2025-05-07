using System;
using System.Threading;
using System.Threading.Tasks;
using AuthSystem.Application.DTOs;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Enums;
using AuthSystem.Core.Interfaces;
using MediatR;
using Microsoft.Extensions.Logging;

namespace AuthSystem.Application.Commands.Authentication
{
    public class AuthenticateCommand : IRequest<AuthResponseDto>
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public bool RememberMe { get; set; }
        public string RecaptchaToken { get; set; }
    }

    public class AuthenticateCommandHandler : IRequestHandler<AuthenticateCommand, AuthResponseDto>
    {
        private readonly IUserRepository _userRepository;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IJwtService _jwtService;
        private readonly IAuditService _auditService;
        private readonly IRecaptchaService _recaptchaService;
        private readonly ILogger<AuthenticateCommandHandler> _logger;

        public AuthenticateCommandHandler(
            IUserRepository userRepository,
            IPasswordHasher passwordHasher,
            IJwtService jwtService,
            IAuditService auditService,
            IRecaptchaService recaptchaService,
            ILogger<AuthenticateCommandHandler> logger)
        {
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
            _jwtService = jwtService;
            _auditService = auditService;
            _recaptchaService = recaptchaService;
            _logger = logger;
        }

        public async Task<AuthResponseDto> Handle(AuthenticateCommand request, CancellationToken cancellationToken)
        {
            try
            {
                // 1. Verificar reCAPTCHA si se proporciona un token
                if (!string.IsNullOrEmpty(request.RecaptchaToken))
                {
                    var isValidRecaptcha = await _recaptchaService.ValidateTokenAsync(
                        request.RecaptchaToken, request.IpAddress);

                    if (!isValidRecaptcha)
                    {
                        await LogFailedLoginAttempt(request, null, "reCAPTCHA inválido");
                        return new AuthResponseDto
                        {
                            Succeeded = false,
                            Error = "Verificación de reCAPTCHA fallida"
                        };
                    }
                }

                // 2. Buscar usuario por nombre de usuario o email
                var user = await _userRepository.FindByUsernameOrEmailAsync(request.Username);

                // 3. Verificar si el usuario existe
                if (user == null)
                {
                    await LogFailedLoginAttempt(request, null, "Usuario no encontrado");
                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = "Credenciales inválidas"
                    };
                }

                // 4. Verificar estado del usuario
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
                        case UserStatus.Deleted:
                            errorMessage = "Esta cuenta ha sido eliminada.";
                            break;
                        default:
                            errorMessage = "La cuenta no está activa.";
                            break;
                    }

                    await LogFailedLoginAttempt(request, user.Id, $"Usuario con estado {user.Status}");
                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = errorMessage
                    };
                }

                // 5. Verificar si la cuenta está bloqueada temporalmente
                if (user.LockoutEnabled && user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.UtcNow)
                {
                    await LogFailedLoginAttempt(request, user.Id, "Cuenta bloqueada temporalmente");

                    // Calcular tiempo restante de bloqueo
                    var remainingTime = user.LockoutEnd.Value - DateTimeOffset.UtcNow;
                    string timeMessage = remainingTime.TotalMinutes >= 1
                        ? $"{Math.Ceiling(remainingTime.TotalMinutes)} minutos"
                        : $"{Math.Ceiling(remainingTime.TotalSeconds)} segundos";

                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = $"Cuenta temporalmente bloqueada. Inténtelo de nuevo en {timeMessage}."
                    };
                }

                // 6. Verificar contraseña
                if (!_passwordHasher.VerifyPassword(user.PasswordHash, request.Password))
                {
                    // Incrementar contador de intentos fallidos
                    user.IncrementAccessFailedCount();

                    // Verificar si se debe bloquear la cuenta
                    if (user.AccessFailedCount >= 5)
                    {
                        user.LockAccount(TimeSpan.FromMinutes(15));
                    }

                    await _userRepository.UpdateAsync(user);
                    //await _userRepository.SaveChangesAsync();

                    await LogFailedLoginAttempt(request, user.Id, "Contraseña incorrecta");

                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = "Credenciales inválidas"
                    };
                }

                // 7. Resetear contador de intentos fallidos si la autenticación es exitosa
                user.ResetAccessFailedCount();
                user.UpdateLastLoginDate();
                await _userRepository.UpdateAsync(user);
               // await _userRepository.SaveChangesAsync();

                // 8. Verificar si se requiere verificación de correo
                if (!user.EmailConfirmed)
                {
                    await LogFailedLoginAttempt(request, user.Id, "Email no confirmado");
                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = "Debe confirmar su dirección de correo electrónico antes de iniciar sesión."
                    };
                }

                // 9. Verificar si se requiere 2FA
                if (user.TwoFactorEnabled)
                {
                    await LogSuccessfulLoginAttempt(request, user.Id, "Requiere 2FA");
                    return new AuthResponseDto
                    {
                        Succeeded = true,
                        RequiresTwoFactor = true,
                        UserId = user.Id
                    };
                }

                // 10. Generar tokens JWT
                var (token, refreshToken) = await _jwtService.GenerateTokensAsync(user, request.RememberMe);

                // 11. Registrar sesión
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

                // 12. Registrar login exitoso
                await LogSuccessfulLoginAttempt(request, user.Id);

                // 13. Mapear usuario a DTO (en una implementación real usarías AutoMapper)
                var userDto = new UserDto
                {
                    Id = user.Id,
                    Username = user.Username,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Status = user.Status.ToString(),
                    LastLoginDate = user.LastLoginDate,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    CreatedAt = user.CreatedAt,
                    // En una implementación real, aquí se incluirían los roles y permisos
                };

                // 14. Retornar resultado exitoso
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
                _logger.LogError(ex, "Error durante la autenticación de usuario {Username}", request.Username);
                return new AuthResponseDto
                {
                    Succeeded = false,
                    Error = "Ha ocurrido un error durante la autenticación. Por favor, inténtelo de nuevo más tarde."
                };
            }
        }

        private async Task LogFailedLoginAttempt(AuthenticateCommand request, Guid? userId, string reason)
        {
            if (_auditService != null)
            {
                await _auditService.LogLoginAttemptAsync(
                    request.Username,
                    request.IpAddress,
                    request.UserAgent,
                    false,
                    reason,
                    userId);
            }
        }

        private async Task LogSuccessfulLoginAttempt(AuthenticateCommand request, Guid userId, string details = null)
        {
            if (_auditService != null)
            {
                await _auditService.LogLoginAttemptAsync(
                    request.Username,
                    request.IpAddress,
                    request.UserAgent,
                    true,
                    details,
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