namespace AuthSystem.Core.Constants
{
    /// <summary>
    /// Claves utilizadas para el sistema de caché.
    /// </summary>
    public static class CacheKeys
    {
        private const string Prefix = "AuthSystem:";

        // Usuario y sesiones
        public const string UserPrefix = Prefix + "User:";
        public static string UserById(string userId) => $"{UserPrefix}{userId}";
        public static string UserByUsername(string username) => $"{UserPrefix}Username:{username}";
        public static string UserByEmail(string email) => $"{UserPrefix}Email:{email}";

        // Roles y permisos
        public const string RolePrefix = Prefix + "Role:";
        public static string RoleById(string roleId) => $"{RolePrefix}{roleId}";
        public static string RoleByName(string roleName) => $"{RolePrefix}Name:{roleName}";

        public const string PermissionPrefix = Prefix + "Permission:";
        public static string PermissionById(string permissionId) => $"{PermissionPrefix}{permissionId}";
        public static string PermissionByCode(string code) => $"{PermissionPrefix}Code:{code}";

        // Módulos
        public const string ModulePrefix = Prefix + "Module:";
        public static string ModuleById(string moduleId) => $"{ModulePrefix}{moduleId}";
        public static string UserModules(string userId) => $"{UserPrefix}{userId}:Modules";

        // Token de verificación
        public const string VerificationTokenPrefix = Prefix + "VerificationToken:";
        public static string EmailVerificationToken(string userId) => $"{VerificationTokenPrefix}Email:{userId}";
        public static string PasswordResetToken(string userId) => $"{VerificationTokenPrefix}Password:{userId}";
        public static string TwoFactorToken(string userId) => $"{VerificationTokenPrefix}2FA:{userId}";

        // Caché general
        public const string SettingsKey = Prefix + "Settings";
        public const string AllPermissionsKey = Prefix + "AllPermissions";
        public const string AllRolesKey = Prefix + "AllRoles";
        public const string AllModulesKey = Prefix + "AllModules";
    }
}