namespace AuthSystem.Core.Constants
{
    /// <summary>
    /// Constantes relacionadas con la seguridad de la aplicación.
    /// </summary>
    public static class SecurityConstants
    {
        // Políticas de contraseñas
        public const int MinPasswordLength = 8;
        public const int MaxPasswordLength = 128;
        public const bool RequireDigit = true;
        public const bool RequireLowercase = true;
        public const bool RequireUppercase = true;
        public const bool RequireNonAlphanumeric = true;
        public const int PasswordHistoryLimit = 5;

        // Bloqueo de cuenta
        public const int MaxFailedAccessAttempts = 5;
        public const int DefaultLockoutTimeInMinutes = 15;

        // Tokens
        public const int RefreshTokenExpirationDays = 7;
        public const int AccessTokenExpirationMinutes = 60;
        public const int EmailConfirmationTokenExpirationDays = 3;
        public const int PasswordResetTokenExpirationHours = 24;
        public const int TwoFactorCodeExpirationMinutes = 5;

        // Formato de tokens
        public const string JwtIssuer = "AuthSystem";
        public const string JwtAudience = "AuthSystemApi";

        // Recaptcha
        public const float RecaptchaMinimumScore = 0.5f;

        // Seguridad de sesión
        public const int SessionIdleTimeoutMinutes = 30;
        public const bool PreventConcurrentSessions = false;
        public const int MaxConcurrentSessions = 5;
    }
}