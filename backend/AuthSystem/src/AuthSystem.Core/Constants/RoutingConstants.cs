namespace AuthSystem.Core.Constants
{
    /// <summary>
    /// Constantes para rutas de la API.
    /// </summary>
    public static class RoutingConstants
    {
        // Base API
        public const string ApiBase = "api/";

        // Controladores
        public const string Auth = ApiBase + "auth";
        public const string Users = ApiBase + "users";
        public const string Roles = ApiBase + "roles";
        public const string Permissions = ApiBase + "permissions";
        public const string Modules = ApiBase + "modules";
        public const string AuditLogs = ApiBase + "audit-logs";
        public const string Settings = ApiBase + "settings";
        public const string Dashboard = ApiBase + "dashboard";
        public const string Profile = ApiBase + "profile";

        // Acciones de autenticación
        public const string Login = "login";
        public const string Register = "register";
        public const string Logout = "logout";
        public const string TwoFactorLogin = "two-factor";
        public const string RefreshToken = "refresh-token";
        public const string ForgotPassword = "forgot-password";
        public const string ResetPassword = "reset-password";
        public const string ChangePassword = "change-password";
        public const string VerifyEmail = "verify-email";

        // Acciones de usuarios
        public const string UserRoles = "roles";
        public const string UserPermissions = "permissions";
        public const string UserSessions = "sessions";
        public const string UserTwoFactor = "two-factor";
    }
}