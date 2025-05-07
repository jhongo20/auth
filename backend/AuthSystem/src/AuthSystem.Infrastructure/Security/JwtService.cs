using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Security/JwtService.cs
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthSystem.Infrastructure.Security
{
    public class JwtService : IJwtService
    {
        private readonly JwtSettings _jwtSettings;
        private readonly IUserRepository _userRepository;
        private readonly IDateTimeProvider _dateTimeProvider;

        public JwtService(
            IOptions<JwtSettings> jwtSettings,
            IUserRepository userRepository,
            IDateTimeProvider dateTimeProvider)
        {
            _jwtSettings = jwtSettings.Value;
            _userRepository = userRepository;
            _dateTimeProvider = dateTimeProvider;
        }

        public async Task<(string Token, string RefreshToken)> GenerateTokensAsync(User user, bool extendedDuration = false)
        {
            // Obtener roles y permisos del usuario
            var roles = await _userRepository.GetUserRolesAsync(user.Id);
            var permissions = await _userRepository.GetUserPermissionsAsync(user.Id);

            // Crear claims para el token
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("name", $"{user.FirstName} {user.LastName}".Trim())
            };

            // Agregar roles
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.Name));
            }

            // Agregar permisos
            foreach (var permission in permissions)
            {
                claims.Add(new Claim("permission", permission.Code));
            }

            // Crear credenciales de firma
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Calcular tiempo de expiración
            var expires = _dateTimeProvider.UtcNow.AddMinutes(
                extendedDuration ? _jwtSettings.ExtendedExpirationMinutes : _jwtSettings.ExpirationMinutes);

            // Crear el token
            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            // Generar refresh token
            var refreshToken = GenerateRefreshToken();

            return (new JwtSecurityTokenHandler().WriteToken(token), refreshToken);
        }

        public async Task<(bool IsValid, string UserId, string Jti)> ValidateTokenAsync(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return (false, null, null);
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);

            try
            {
                // Validar token
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _jwtSettings.Issuer,
                    ValidateAudience = true,
                    ValidAudience = _jwtSettings.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userId = jwtToken.Claims.First(x => x.Type == JwtRegisteredClaimNames.Sub).Value;
                var jti = jwtToken.Claims.First(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                // Verificar si el token ha sido revocado
                if (await _userRepository.IsTokenRevokedAsync(Guid.Parse(userId), jti))
                {
                    return (false, null, null);
                }

                return (true, userId, jti);
            }
            catch
            {
                // Devolver falso si la validación falla
                return (false, null, null);
            }
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }

    public class JwtSettings
    {
        public string Secret { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int ExpirationMinutes { get; set; }
        public int ExtendedExpirationMinutes { get; set; }
        public int RefreshTokenExpirationDays { get; set; }
    }
}
