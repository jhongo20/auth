namespace AuthSystem.Core.Constants
{
    /// <summary>
    /// Códigos de permisos del sistema.
    /// </summary>
    public static class PermissionConstants
    {
        // Permisos de usuarios
        public const string ViewUsers = "users.view";
        public const string CreateUsers = "users.create";
        public const string UpdateUsers = "users.update";
        public const string DeleteUsers = "users.delete";
        public const string ManageUserRoles = "users.manage.roles";
        public const string ManageUserPermissions = "users.manage.permissions";

        // Permisos de roles
        public const string ViewRoles = "roles.view";
        public const string CreateRoles = "roles.create";
        public const string UpdateRoles = "roles.update";
        public const string DeleteRoles = "roles.delete";
        public const string ManageRolePermissions = "roles.manage.permissions";

        // Permisos de módulos
        public const string ViewModules = "modules.view";
        public const string CreateModules = "modules.create";
        public const string UpdateModules = "modules.update";
        public const string DeleteModules = "modules.delete";

        // Permisos de auditoría
        public const string ViewAuditLogs = "audit.view";
        public const string ExportAuditLogs = "audit.export";

        // Permisos de configuración
        public const string ViewSettings = "settings.view";
        public const string UpdateSettings = "settings.update";

        // Permisos de perfil
        public const string ViewProfile = "profile.view";
        public const string UpdateProfile = "profile.update";
        public const string ManageTwoFactor = "profile.manage.2fa";

        // Permisos del dashboard
        public const string ViewDashboard = "dashboard.view";
    }
}