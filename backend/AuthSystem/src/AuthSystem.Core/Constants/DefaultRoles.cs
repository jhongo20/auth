using AuthSystem.Core.Enums;

namespace AuthSystem.Core.Constants
{
    /// <summary>
    /// Roles predefinidos del sistema.
    /// </summary>
    public static class DefaultRoles
    {
        public const string SuperAdmin = "SuperAdmin";
        public const string Admin = "Admin";
        public const string Manager = "Manager";
        public const string Supervisor = "Supervisor";
        public const string User = "User";
        public const string ReadOnly = "ReadOnly";
        public const string Guest = "Guest";

        // Descripción de los roles predefinidos
        public static readonly (string Name, string Description, RoleType Type, bool IsDefault) SuperAdminRole
            = (SuperAdmin, "Acceso completo a todas las funcionalidades del sistema", RoleType.SuperAdmin, false);

        public static readonly (string Name, string Description, RoleType Type, bool IsDefault) AdminRole
            = (Admin, "Administrador del sistema con altos privilegios", RoleType.Admin, false);

        public static readonly (string Name, string Description, RoleType Type, bool IsDefault) ManagerRole
            = (Manager, "Puede gestionar usuarios y algunas configuraciones", RoleType.Manager, false);

        public static readonly (string Name, string Description, RoleType Type, bool IsDefault) SupervisorRole
            = (Supervisor, "Supervisa actividades pero con acceso limitado", RoleType.Supervisor, false);

        public static readonly (string Name, string Description, RoleType Type, bool IsDefault) UserRole
            = (User, "Usuario regular con funcionalidades básicas", RoleType.User, true);

        public static readonly (string Name, string Description, RoleType Type, bool IsDefault) ReadOnlyRole
            = (ReadOnly, "Usuario con acceso de solo lectura", RoleType.ReadOnly, false);

        public static readonly (string Name, string Description, RoleType Type, bool IsDefault) GuestRole
            = (Guest, "Acceso mínimo para usuarios no registrados", RoleType.Guest, false);
    }
}