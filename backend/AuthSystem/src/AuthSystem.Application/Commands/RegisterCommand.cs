using System;
using System.Threading;
using System.Threading.Tasks;
using AuthSystem.Application.DTOs;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using MediatR;
using Microsoft.Extensions.Logging;

namespace AuthSystem.Application.Commands.Authentication
{
    public class RegisterCommand : IRequest<AuthResponseDto>
    {

        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public string RecaptchaToken { get; set; }
    }

    public class RegisterCommandHandler : IRequestHandler<RegisterCommand, AuthResponseDto>
    {
        private readonly IUserRepository _userRepository;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IEmailService _emailService;
        private readonly IRecaptchaService _recaptchaService;
        private readonly IAuditService _auditService;
        private readonly ILogger<RegisterCommandHandler> _logger;

        public RegisterCommandHandler(
            IUserRepository userRepository,
            IPasswordHasher passwordHasher,
            IEmailService emailService,
            IRecaptchaService recaptchaService,
             IAuditService auditService,
            ILogger<RegisterCommandHandler> logger)
        {
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
            _emailService = emailService;
            _recaptchaService = recaptchaService;
            _auditService = auditService;
            _logger = logger;
        }

        public async Task<AuthResponseDto> Handle(RegisterCommand request, CancellationToken cancellationToken)
        {
            try
            {
                // 1. Verificar reCAPTCHA si se proporciona
                if (!string.IsNullOrEmpty(request.RecaptchaToken))
                {
                    var isValidRecaptcha = await _recaptchaService.ValidateTokenAsync(
                        request.RecaptchaToken, request.IpAddress);

                    if (!isValidRecaptcha)
                    {
                        return new AuthResponseDto
                        {
                            Succeeded = false,
                            Error = "Verificación de reCAPTCHA fallida"
                        };
                    }
                }

                // 2. Verificar si el nombre de usuario ya existe
                //var existingUserByUsername = await _userRepository.FindByUsernameAsync(request.Username);

                // With this line:
                var existingUserByUsername = await _userRepository.GetByUsernameAsync(request.Username);


                if (existingUserByUsername != null)
                {
                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = "El nombre de usuario ya está en uso"
                    };
                }

                // 3. Verificar si el correo electrónico ya existe
                //var existingUserByEmail = await _userRepository.FindByEmailAsync(request.Email);

                // With this line:
                var existingUserByEmail = await _userRepository.GetByEmailAsync(request.Email);

                if (existingUserByEmail != null)
                {
                    return new AuthResponseDto
                    {
                        Succeeded = false,
                        Error = "El correo electrónico ya está registrado"
                    };
                }

                // 4. Generar hash de la contraseña
                var passwordHash = _passwordHasher.HashPassword(request.Password);

                // 5. Crear el nuevo usuario
                var user = new Core.Entities.User(
                    request.Username,
                    request.Email,
                    passwordHash,
                    request.FirstName,
                    request.LastName);

                // 6. Guardar el usuario en la base de datos
                //await _userRepository.AddAsync(user);
                await _userRepository.CreateAsync(user);


                // await _userRepository.SaveChangesAsync();
                await _userRepository.UpdateAsync(user);

                // 7. Asignar rol por defecto (opcional)
                try
                {
                    // Buscar el rol de usuario por defecto usando el nuevo método
                    var defaultRole = await _userRepository.GetRoleByNameAsync("User");
                    if (defaultRole != null)
                    {
                        await _userRepository.AddToRoleAsync(user.Id, defaultRole.Id);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "No se pudo asignar el rol por defecto al usuario {UserId}", user.Id);
                    // No fallamos el registro por esto, continuamos
                }

                // 8. Generar token de confirmación
                var tokenBytes = new byte[32];
                using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
                rng.GetBytes(tokenBytes);
                string token = Convert.ToBase64String(tokenBytes);

                // 9. Almacenar token usando el nuevo método
                await _userRepository.StoreEmailConfirmationTokenAsync(user.Id, token);

                // 10. Enviar correo de confirmación
                try
                {
                    await _emailService.SendConfirmationEmailAsync(user.Email, user.Id.ToString(), token);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error al enviar el correo de confirmación para el usuario {UserId}", user.Id);
                    // No fallamos el registro, pero registramos el error
                }

                // 11. Registrar acción en auditoría
                if (_auditService != null)
                {
                    await _auditService.LogActionAsync(
                        user.Id,
                        "Register",
                        "User",
                        user.Id.ToString(),
                        null,
                        new { Id = user.Id, Username = user.Username, Email = user.Email },
                        request.IpAddress,
                        request.UserAgent);
                }

                // 12. Devolver respuesta exitosa
                return new AuthResponseDto
                {
                    Succeeded = true,
                    Error = null,
                    Message = "Registro exitoso. Por favor revisa tu correo electrónico para activar tu cuenta."
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante el registro del usuario {Username}", request.Username);
                return new AuthResponseDto
                {
                    Succeeded = false,
                    Error = "Ha ocurrido un error durante el registro. Por favor, inténtalo de nuevo más tarde."
                };
            }
        }

        // Método auxiliar para generar un token aleatorio
        private string GenerateRandomToken()
        {
            var randomNumber = new byte[32];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}