namespace AuthSystem.Core.Constants
{
    /// <summary>
    /// Claves de configuración utilizadas en la aplicación.
    /// </summary>
    public static class ConfigurationKeys
    {
        // Secciones de configuración
        public const string JwtSettingsSection = "JwtSettings";
        public const string EmailSettingsSection = "EmailSettings";
        public const string RecaptchaSettingsSection = "RecaptchaSettings";
        public const string PasswordPolicySection = "PasswordPolicy";

        // Llaves específicas
        public const string ConnectionStringKey = "DefaultConnection";
        public const string RedisConnectionStringKey = "RedisConnection";
        public const string AllowedOriginsKey = "AllowedOrigins";
        public const string UseRedisCacheKey = "UseRedisCache";

        // Configuración de correo
        public const string SmtpHost = "SmtpHost";
        public const string SmtpPort = "SmtpPort";
        public const string SmtpUsername = "Username";
        public const string SmtpPassword = "Password";
        public const string SmtpEnableSsl = "EnableSsl";
        public const string EmailFromAddress = "FromEmail";
        public const string EmailFromName = "FromName";

        // Configuración JWT
        public const string JwtSecret = "Secret";
        public const string JwtIssuer = "Issuer";
        public const string JwtAudience = "Audience";
        public const string JwtExpirationMinutes = "ExpirationMinutes";

        // Configuración reCAPTCHA
        public const string RecaptchaSiteKey = "SiteKey";
        public const string RecaptchaSecretKey = "SecretKey";
    }
}