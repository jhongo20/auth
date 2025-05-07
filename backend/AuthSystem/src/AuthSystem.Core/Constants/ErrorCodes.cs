namespace AuthSystem.Core.Constants
{
    /// <summary>
    /// Códigos de error para respuestas de API consistentes.
    /// </summary>
    public static class ErrorCodes
    {
        // Códigos de error generales (1000-1999)
        public const string GeneralError = "ERR1000";
        public const string ValidationError = "ERR1001";
        public const string NotFoundError = "ERR1002";
        public const string DuplicateError = "ERR1003";
        public const string UnauthorizedError = "ERR1004";
        public const string ForbiddenError = "ERR1005";
        public const string ConfigurationError = "ERR1006";
        public const string DatabaseError = "ERR1007";
        public const string ExternalServiceError = "ERR1008";

        // Códigos de error de autenticación (2000-2999)
        public const string InvalidCredentials = "ERR2000";
        public const string AccountLocked = "ERR2001";
        public const string AccountDisabled = "ERR2002";
        public const string EmailNotConfirmed = "ERR2003";
        public const string TwoFactorRequired = "ERR2004";
        public const string InvalidTwoFactorCode = "ERR2005";
        public const string TokenExpired = "ERR2006";
        public const string InvalidToken = "ERR2007";
        public const string RecaptchaFailed = "ERR2008";
        public const string PasswordChangeRequired = "ERR2009";
        public const string TooManyAttempts = "ERR2010";

        // Códigos de error de usuario (3000-3999)
        public const string UserNotFound = "ERR3000";
        public const string UsernameTaken = "ERR3001";
        public const string EmailTaken = "ERR3002";
        public const string InvalidPassword = "ERR3003";
        public const string PasswordHistoryViolation = "ERR3004";
        public const string InvalidUserStatus = "ERR3005";

        // Códigos de error de roles y permisos (4000-4999)
        public const string RoleNotFound = "ERR4000";
        public const string PermissionNotFound = "ERR4001";
        public const string PermissionDenied = "ERR4002";
        public const string RoleNameTaken = "ERR4003";
        public const string PermissionCodeTaken = "ERR4004";
        public const string DefaultRoleNotDeletable = "ERR4005";

        // Códigos de error de módulos (5000-5999)
        public const string ModuleNotFound = "ERR5000";
        public const string ModuleNameTaken = "ERR5001";
        public const string CircularModuleDependency = "ERR5002";
    }
}