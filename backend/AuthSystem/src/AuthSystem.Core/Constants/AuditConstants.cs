namespace AuthSystem.Core.Constants
{
    /// <summary>
    /// Constantes para el sistema de auditoría.
    /// </summary>
    public static class AuditConstants
    {
        // Nombres de entidades
        public const string UserEntity = "User";
        public const string RoleEntity = "Role";
        public const string PermissionEntity = "Permission";
        public const string ModuleEntity = "Module";
        public const string SettingEntity = "Setting";

        // Acciones de auditoría
        public const string CreateAction = "Create";
        public const string ReadAction = "Read";
        public const string UpdateAction = "Update";
        public const string DeleteAction = "Delete";
        public const string LoginAction = "Login";
        public const string LogoutAction = "Logout";
        public const string FailedLoginAction = "FailedLogin";
        public const string PasswordChangeAction = "PasswordChange";
        public const string PasswordResetAction = "PasswordReset";

        // Categorías de auditoría
        public const string SecurityCategory = "Security";
        public const string UserManagementCategory = "UserManagement";
        public const string SystemConfigCategory = "SystemConfig";
        public const string DataAccessCategory = "DataAccess";
    }
}